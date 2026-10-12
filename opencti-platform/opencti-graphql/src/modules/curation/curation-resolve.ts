import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import { FunctionalError } from '../../config/errors';
import { internalFindByIds, pageEntitiesConnection, topEntitiesList } from '../../database/middleware-loader';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { ALIAS_FILTER } from '../../utils/filtering/filtering-constants';
import { getInputIds } from '../../schema/identifier';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { convertTypeToStixType } from '../../database/stix-2-1-converter';
import { resolveAliasesField } from '../../schema/stixDomainObject';
import { addCurationResolveCount } from '../../manager/telemetryManager';
import { canonicalizeEntityNames, canonicalizeName, getTaxonomyFamily, trigramSimilarity } from './curation-normalization';
import { findTaxonomyClusters, getTaxonomySourceReliability } from './curation-taxonomy';

export interface CurationResolution {
  entity_id: string;
  standard_id: string;
  entity_type: string;
  name: string;
  match_type: 'exact' | 'alias' | 'canonical' | 'taxonomy' | 'similarity';
  score: number;
  matched_value: string;
}

const MAX_NAME_LENGTH = 512;
const BINDING_THRESHOLD = 0.85;
const SIMILARITY_BINDING_THRESHOLD = 0.92;
const SEARCH_CANDIDATES = 50;

/**
 * Accept an OpenCTI entity type ("Intrusion-Set") or a STIX type ("intrusion-set", "threat-actor").
 */
export const resolveResolutionTypes = (type: string): string[] => {
  const normalized = (type ?? '').trim().toLowerCase();
  if (!normalized) return [];
  const domainTypes = schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT) as string[];
  const exact = domainTypes.filter((domainType) => domainType.toLowerCase() === normalized);
  if (exact.length > 0) return exact;
  return domainTypes.filter((domainType) => convertTypeToStixType(domainType) === normalized);
};

const namesOf = (entity: BasicStoreEntity): string[] => {
  const aliasField = resolveAliasesField(entity.entity_type).name;
  return [entity.name, ...(((entity as Record<string, any>)[aliasField] ?? []) as string[])].filter(Boolean);
};

const toResolution = (entity: BasicStoreEntity, match: CurationResolution['match_type'], score: number, matched: string): CurationResolution => ({
  entity_id: entity.internal_id,
  standard_id: entity.standard_id,
  entity_type: entity.entity_type,
  name: entity.name,
  match_type: match,
  score: Math.round(score * 1000) / 1000,
  matched_value: matched,
});

/**
 * Keep the best resolution, but only if it is unambiguous: two different entities at the best score mean the name
 * cannot be bound safely and nothing is returned.
 */
export const pickUnambiguous = (resolutions: CurationResolution[], threshold: number): CurationResolution | null => {
  const eligible = resolutions.filter((resolution) => resolution.score >= threshold);
  if (eligible.length === 0) return null;
  const best = Math.max(...eligible.map((resolution) => resolution.score));
  const top = R.uniqBy((resolution) => resolution.entity_id, eligible.filter((resolution) => resolution.score === best));
  return top.length === 1 ? top[0] : null;
};

// Every entity carrying the name as an alias, not only those the capped fuzzy search would hold: an alias decides alone.
const aliasFilters = (name: string) => ({
  mode: FilterMode.And,
  filters: [{ key: [ALIAS_FILTER], values: [name], operator: FilterOperator.Eq, mode: FilterMode.Or }],
  filterGroups: [],
});

const exactResolutions = async (context: AuthContext, user: AuthUser, name: string, types: string[]): Promise<CurationResolution[]> => {
  const ids = R.uniq(types.flatMap((type) => {
    try {
      return getInputIds(type, { name, entity_type: type });
    } catch {
      return [];
    }
  }));
  const [byIds, byAliases] = await Promise.all([
    ids.length > 0 ? internalFindByIds(context, user, ids, { type: types }) as Promise<BasicStoreEntity[]> : [],
    topEntitiesList<BasicStoreEntity>(context, user, types, { filters: aliasFilters(name), first: SEARCH_CANDIDATES }),
  ]);
  const found = R.uniqBy((entity) => entity.internal_id, [...byIds, ...byAliases]);
  const lowered = name.trim().toLowerCase();
  return found.flatMap((entity) => {
    const matched = namesOf(entity).find((value) => value.trim().toLowerCase() === lowered);
    // Found through one of its other STIX identifiers only: the entity does not carry the name.
    if (!matched) return [];
    const isName = (entity.name ?? '').trim().toLowerCase() === lowered;
    return [toResolution(entity, isName ? 'exact' : 'alias', isName ? 1 : 0.98, matched)];
  });
};

const fuzzyResolutions = async (context: AuthContext, user: AuthUser, name: string, types: string[]): Promise<CurationResolution[]> => {
  const resolutions: CurationResolution[] = [];
  const query = canonicalizeEntityNames([name], types[0]);
  const queryStripped = new Set([...query.stripped, ...query.full]);
  const searchTerms = R.uniq([name, ...name.split(/[\s\-_.]+/).filter((token) => token.length >= 4)]).slice(0, 4);
  const candidates = new Map<string, BasicStoreEntity>();
  for (let index = 0; index < searchTerms.length; index += 1) {
    const page = await pageEntitiesConnection<BasicStoreEntity>(context, user, types, { search: searchTerms[index], first: SEARCH_CANDIDATES });
    page.edges.forEach(({ node }) => candidates.set(node.internal_id, node));
  }
  // Taxonomy: names the vendor taxonomy lists for the same object are looked up by identifier.
  const family = getTaxonomyFamily(types[0]);
  if (family) {
    const clusters = findTaxonomyClusters(query.full, family);
    const clusterNames = R.uniq(clusters.flatMap((cluster) => cluster.names)).slice(0, 60);
    const clusterIds = R.uniq(types.flatMap((type) => clusterNames.flatMap((clusterName) => {
      try {
        return getInputIds(type, { name: clusterName, entity_type: type });
      } catch {
        return [];
      }
    })));
    if (clusterIds.length > 0) {
      const found = await internalFindByIds(context, user, clusterIds, { type: types }) as BasicStoreEntity[];
      found.forEach((entity) => {
        candidates.set(entity.internal_id, entity);
        const entityForms = canonicalizeEntityNames(namesOf(entity), entity.entity_type).full;
        const cluster = clusters.find((c) => [...entityForms].some((form) => c.canonicals.has(form)));
        if (cluster) {
          const matched = namesOf(entity).find((value) => [...canonicalizeName(value, entity.entity_type).full].some((form) => cluster.canonicals.has(form))) ?? entity.name;
          resolutions.push(toResolution(entity, 'taxonomy', getTaxonomySourceReliability(cluster.source), matched));
        }
      });
    }
  }
  candidates.forEach((entity) => {
    const names = namesOf(entity);
    names.forEach((value) => {
      const forms = canonicalizeName(value, entity.entity_type);
      if ([...forms.full].some((form) => query.full.has(form))) {
        resolutions.push(toResolution(entity, 'canonical', 0.95, value));
      } else if ([...forms.full, ...forms.stripped].some((form) => queryStripped.has(form))) {
        resolutions.push(toResolution(entity, 'canonical', 0.86, value));
      }
      const similarity = trigramSimilarity(name, value);
      if (similarity >= SIMILARITY_BINDING_THRESHOLD) {
        resolutions.push(toResolution(entity, 'similarity', similarity * 0.95, value));
      }
    });
  });
  return resolutions;
};

/**
 * Resolve a name extracted by an importer to an existing entity of the given type, with the access rights of the
 * caller. Exact name or alias matches first, then canonical forms (case, punctuation, vendor suffixes, digits used as
 * letters), the vendor taxonomy and trigram similarity. Ambiguous matches return null: never bind to a coin flip.
 * When exact or alias matches exist they decide alone: the fuzzy search is capped and ordered by relevance, so it may
 * hold only one of the entities that share the name.
 */
export const curationResolve = async (context: AuthContext, user: AuthUser, name: string, type: string): Promise<CurationResolution | null> => {
  const trimmed = (name ?? '').trim();
  if (trimmed.length === 0 || trimmed.length > MAX_NAME_LENGTH) {
    throw FunctionalError('The name to resolve must contain between 1 and 512 characters');
  }
  const types = resolveResolutionTypes(type);
  if (types.length === 0) {
    throw FunctionalError('Unknown entity type for resolution', { type });
  }
  const exactCandidates = await exactResolutions(context, user, trimmed, types);
  if (exactCandidates.length > 0) {
    const exact = pickUnambiguous(exactCandidates, BINDING_THRESHOLD);
    addCurationResolveCount(exact !== null);
    return exact;
  }
  const fuzzy = pickUnambiguous(await fuzzyResolutions(context, user, trimmed, types), BINDING_THRESHOLD);
  addCurationResolveCount(fuzzy !== null);
  return fuzzy;
};
