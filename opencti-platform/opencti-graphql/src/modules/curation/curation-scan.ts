import * as R from 'ramda';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import { fullEntitiesList, fullRelationsList, internalFindByIds, pageEntitiesConnection, pageRelationsConnection } from '../../database/middleware-loader';
import { redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { elAggregationRelationsCount, elIndexExists, elRawSearch } from '../../database/engine';
import { ES_INDEX_PREFIX, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { CURATION_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { logApp } from '../../config/conf';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { RELATION_ATTRIBUTED_TO, RELATION_BASED_ON, RELATION_RELATED_TO, RELATION_TARGETS, RELATION_USES } from '../../schema/stixCoreRelationship';
import {
  ENTITY_TYPE_ATTACK_PATTERN,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INCIDENT,
  ENTITY_TYPE_INFRASTRUCTURE,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_TOOL,
  resolveAliasesField,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../organization/organization-types';
import { ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL } from '../threatActorIndividual/threatActorIndividual-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import {
  type BasicStoreEntityCurationProposal,
  type BasicStoreEntityMergeRecord,
  type CurationCandidateEntity,
  type CurationSettings,
  DETECTOR_BEHAVIOR,
  DETECTOR_CONTRADICTION,
  DETECTOR_NORMALIZATION,
  DETECTOR_SIMILARITY,
  DETECTOR_STALENESS,
  ENTITY_TYPE_CURATION_PROPOSAL,
  ENTITY_TYPE_MERGE_RECORD,
  MERGE_STATUS_ACTIVE,
  MERGE_STATUS_PARTIALLY_REVERTED,
  PROPOSAL_KIND_ALIAS,
  PROPOSAL_KIND_CONTRADICTION,
  PROPOSAL_KIND_MERGE,
  PROPOSAL_KIND_TYPE_MISMATCH,
  PROPOSAL_STATUS_REJECTED,
  type ProposalDraft,
} from './curation-types';
import {
  buildAttributionConflictDraft,
  buildDateInversionDraft,
  buildPairDraft,
  buildRevokedIndicatorDraft,
  buildSplitDraft,
  buildStaleDraft,
  type CuratedEntity,
  detectBehaviorPairs,
  detectCanonicalCollisions,
  detectDescriptionPairs,
  detectMissingAliases,
  detectTaxonomyPairs,
  detectTrigramPairs,
  emptyNeighborSets,
  isDecayedToRevocation,
  observablesActiveSinceRevocation,
  isDuplicateDetectionEnabled,
  type NeighborSets,
  type PairSignals,
  pairKey,
  selectMergeTarget,
  toCuratedEntity,
} from './curation-detectors';
import { getTaxonomyFamily } from './curation-normalization';
import { findTaxonomyClusters } from './curation-taxonomy';
import { generateAliasesId } from '../../schema/identifier';
import { persistProposalDraft } from './curation-proposals';
import { getStalenessMonths } from './curation-settings';

const ID_CHUNK = 500;
const MAX_CONTRADICTIONS_PER_TYPE = 2000;
const MAX_STALE_PER_TYPE = 2000;
const MAX_REVOKED_INDICATORS = 5000;
const MAX_DISTINCT_PAIRS = 2000;
const GRAPH_SIMILARITY_INDEX = `${ES_INDEX_PREFIX}_graph_similarity`;
const OBSERVABLE_INFRASTRUCTURE_TYPES = ['IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Url', 'Email-Addr', 'Hostname'];
const VICTIM_TYPES = [ENTITY_TYPE_IDENTITY_SECTOR, ENTITY_TYPE_LOCATION_COUNTRY, ENTITY_TYPE_LOCATION_REGION, ENTITY_TYPE_LOCATION_CITY, ENTITY_TYPE_IDENTITY_ORGANIZATION];
const BEHAVIOR_TYPES = [
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
  ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL,
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_TOOL,
];

export interface ScanStats {
  scanned: number;
  drafts: number;
  created: number;
  suppressed: number;
}

const emptyStats = (): ScanStats => ({ scanned: 0, drafts: 0, created: 0, suppressed: 0 });

const isEnabled = (settings: CurationSettings, detector: string) => settings.curation_enabled && (settings.enabled_detectors as string[]).includes(detector);

// region loading
export const toCandidate = (raw: BasicStoreEntity & Record<string, any>): CurationCandidateEntity => {
  const aliasField = resolveAliasesField(raw.entity_type).name;
  const creator = raw.creator_id;
  return {
    internal_id: raw.internal_id,
    standard_id: raw.standard_id,
    entity_type: raw.entity_type,
    name: raw.name ?? '',
    aliases: (raw[aliasField] ?? []) as string[],
    description: typeof raw.description === 'string' ? raw.description : null,
    created_by_id: (Array.isArray(raw[RELATION_CREATED_BY]) ? raw[RELATION_CREATED_BY][0] : raw[RELATION_CREATED_BY]) ?? null,
    creator_ids: (Array.isArray(creator) ? creator : [creator]).filter((id): id is string => typeof id === 'string' && id.length > 0),
    marking_ids: raw[RELATION_OBJECT_MARKING] ?? [],
    organization_ids: raw[RELATION_GRANTED_TO] ?? [],
    updated_at: raw.updated_at ? new Date(raw.updated_at).toISOString() : null,
    x_opencti_assertions: Array.isArray(raw.x_opencti_assertions) ? raw.x_opencti_assertions : null,
    x_opencti_graph_metrics: raw.x_opencti_graph_metrics ?? null,
  };
};

const SCAN_ROTATION_STATE = 'curation_scan_rotation_';
const MAX_ROTATING_SLICE = 5000;

interface RotatingPage<T> {
  edges: Array<{ node: T }>;
  pageInfo: { hasNextPage: boolean; endCursor?: string | null };
}

/**
 * The next page of a scan larger than one run, from where the previous scan stopped: the cursor goes back to the
 * start once the last page is read, so successive scans cover every matching element instead of the same window.
 */
const loadRotatingPage = async <T>(name: string, loadPage: (after: string | undefined) => Promise<RotatingPage<T>>) => {
  const stateKey = `${SCAN_ROTATION_STATE}${name}`;
  const after = (await redisGetManagerEventState(stateKey)) || undefined;
  let page: RotatingPage<T>;
  try {
    page = await loadPage(after);
  } catch (error) {
    if (!after) throw error;
    logApp.warn('[CURATION] Cannot resume a scan from its cursor, starting over', { cause: error, scan: name });
    page = await loadPage(undefined);
  }
  await redisSetManagerEventState(stateKey, page.pageInfo.hasNextPage ? (page.pageInfo.endCursor ?? '') : '');
  return page.edges.map((edge) => edge.node);
};

/** The next slice of the entities of a type in creation order (see loadRotatingPage). */
const loadRotatingSlice = async (context: AuthContext, type: string, size: number) => {
  return loadRotatingPage(type, (after) => pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, [type], {
    first: size,
    after,
    orderBy: 'created_at',
    orderMode: 'asc',
  } as any));
};

/**
 * Entities a scheduled scan compares, per type: the most recently updated half of the budget, and a rotating slice of
 * the others for the second half, so that over successive scans every entity is compared with the recent ones.
 * Entities that change are compared with the whole graph by the incremental detection.
 */
export const loadCuratedEntities = async (context: AuthContext, types: string[], maxPerType: number): Promise<CuratedEntity[]> => {
  const entities: CuratedEntity[] = [];
  const recentSize = Math.ceil(maxPerType / 2);
  const rotatingSize = Math.min(maxPerType - recentSize, MAX_ROTATING_SLICE);
  for (let index = 0; index < types.length; index += 1) {
    const recent = await fullEntitiesList<BasicStoreEntity>(context, CURATION_MANAGER_USER, [types[index]], {
      maxSize: recentSize,
      orderBy: 'updated_at',
      orderMode: 'desc',
    } as any);
    const recentIds = new Set(recent.map((element) => element.internal_id));
    const rotating = rotatingSize > 0 ? await loadRotatingSlice(context, types[index], rotatingSize) : [];
    [...recent, ...rotating.filter((element) => !recentIds.has(element.internal_id))]
      .forEach((element) => entities.push(toCuratedEntity(toCandidate(element as BasicStoreEntity & Record<string, any>))));
  }
  return entities;
};

const addNeighbor = (neighbors: Map<string, NeighborSets>, id: string, key: keyof NeighborSets, value: string) => {
  let sets = neighbors.get(id);
  if (!sets) {
    sets = emptyNeighborSets();
    neighbors.set(id, sets);
  }
  sets[key].add(value);
};

/**
 * Behavioral neighborhood of entities: ATT&CK techniques, tools and malware, infrastructure (including observables),
 * victims, and the campaigns or incidents attributed to them.
 */
export const loadNeighborSets = async (context: AuthContext, entityIds: string[]): Promise<Map<string, NeighborSets>> => {
  const neighbors = new Map<string, NeighborSets>();
  const chunks = R.splitEvery(ID_CHUNK, entityIds);
  for (let index = 0; index < chunks.length; index += 1) {
    const fromId = chunks[index];
    const collect = (key: keyof NeighborSets) => async (relations: BasicStoreRelation[]) => {
      relations.forEach((relation) => addNeighbor(neighbors, relation.fromId, key, relation.toId));
    };
    await fullRelationsList(context, CURATION_MANAGER_USER, RELATION_USES, { fromId, toTypes: [ENTITY_TYPE_ATTACK_PATTERN], baseData: true, callback: collect('techniques') });
    await fullRelationsList(context, CURATION_MANAGER_USER, RELATION_USES, { fromId, toTypes: [ENTITY_TYPE_MALWARE, ENTITY_TYPE_TOOL], baseData: true, callback: collect('tools') });
    await fullRelationsList(context, CURATION_MANAGER_USER, [RELATION_USES, RELATION_RELATED_TO], {
      fromId,
      toTypes: [ENTITY_TYPE_INFRASTRUCTURE, ...OBSERVABLE_INFRASTRUCTURE_TYPES],
      baseData: true,
      callback: collect('infrastructure'),
    });
    await fullRelationsList(context, CURATION_MANAGER_USER, RELATION_TARGETS, { fromId, toTypes: VICTIM_TYPES, baseData: true, callback: collect('victims') });
    await fullRelationsList(context, CURATION_MANAGER_USER, RELATION_ATTRIBUTED_TO, {
      toId: fromId,
      fromTypes: [ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_INCIDENT],
      baseData: true,
      callback: async (relations: BasicStoreRelation[]) => {
        relations.forEach((relation) => addNeighbor(neighbors, relation.toId, 'campaigns', relation.fromId));
      },
    });
  }
  return neighbors;
};

export const isGraphSimilarityAvailable = async () => {
  try {
    return await elIndexExists(GRAPH_SIMILARITY_INDEX);
  } catch {
    return false;
  }
};

/**
 * Soft integration with the knowledge graph analytics (structural similarity cache): used when present, ignored
 * otherwise. The cache shape is read defensively.
 */
export const loadGraphSimilarity = async (context: AuthContext, entityIds: string[]): Promise<Map<string, { score: number; shared?: unknown }>> => {
  const result = new Map<string, { score: number; shared?: unknown }>();
  if (entityIds.length === 0) return result;
  try {
    if (!(await elIndexExists(GRAPH_SIMILARITY_INDEX))) return result;
    const chunks = R.splitEvery(ID_CHUNK, entityIds);
    const idSet = new Set(entityIds);
    for (let index = 0; index < chunks.length; index += 1) {
      const response = await elRawSearch(context, SYSTEM_USER, null, {
        index: GRAPH_SIMILARITY_INDEX,
        size: 5000,
        query: { bool: { should: [{ terms: { 'entity_id.keyword': chunks[index] } }, { terms: { entity_id: chunks[index] } }], minimum_should_match: 1 } },
      });
      (response?.hits?.hits ?? []).forEach((hit: any) => {
        const source = hit._source ?? {};
        if (typeof source.entity_id === 'string' && typeof source.similar_id === 'string' && idSet.has(source.similar_id) && typeof source.score === 'number') {
          const key = pairKey(source.entity_id, source.similar_id);
          const current = result.get(key);
          if (!current || current.score < source.score) result.set(key, { score: Math.min(1, Math.max(0, source.score)), shared: source.shared });
        }
      });
    }
  } catch (error) {
    logApp.debug('[CURATION] Graph similarity cache not usable, ignored', { cause: error });
  }
  return result;
};

// The engine returns at most 100 buckets per relationship aggregation: a chunk never names more entities than that.
const RELATIONSHIP_COUNT_CHUNK = 100;

/**
 * Relationship counts of the given entities, each entity counted once whatever the number of pairs it is part of: one
 * aggregation on the relationship connections per chunk of entities. An entity without relationships has no entry.
 */
export const countRelationshipsByEntity = async (context: AuthContext, entityIds: string[]) => {
  const counts = new Map<string, number>();
  const chunks = R.splitEvery(RELATIONSHIP_COUNT_CHUNK, R.uniq(entityIds));
  for (let index = 0; index < chunks.length; index += 1) {
    const filters = {
      mode: FilterMode.And,
      filters: [{ key: ['connections'], nested: [{ key: 'internal_id', values: chunks[index] }], values: [] }],
      filterGroups: [],
    };
    const buckets = await elAggregationRelationsCount(context, SYSTEM_USER, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
      types: [ABSTRACT_STIX_CORE_RELATIONSHIP],
      field: 'internal_id',
      searchOptions: { types: [ABSTRACT_STIX_CORE_RELATIONSHIP], filters, noFiltersChecking: true },
      aggregationOptions: { filters, noFiltersChecking: true },
    } as any);
    buckets.forEach(({ label, value }) => counts.set(label, value));
  }
  return counts;
};
// endregion

const persistDrafts = async (context: AuthContext, settings: CurationSettings, drafts: ProposalDraft[], stats: ScanStats) => {
  for (let index = 0; index < drafts.length; index += 1) {
    try {
      const result = await persistProposalDraft(context, settings, drafts[index]);
      if (result.created) stats.created += 1;
      if (result.suppressed) stats.suppressed += 1;
    } catch (error) {
      logApp.warn('[CURATION] Cannot persist a curation proposal', { cause: error, kind: drafts[index].kind });
    }
  }

  stats.drafts += drafts.length;
};

// region duplicates (detectors 1, 2, 3)
const scanGroups = (types: string[]): string[][] => {
  const byFamily = R.groupBy((type: string) => getTaxonomyFamily(type) ?? type, types);
  return Object.values(byFamily) as string[][];
};

export const detectDuplicateDrafts = async (
  context: AuthContext,
  settings: CurationSettings,
  entities: CuratedEntity[],
  focusIds?: Set<string>,
): Promise<ProposalDraft[]> => {
  const pairs = new Map<string, PairSignals>();
  const drafts: ProposalDraft[] = [];
  if (isEnabled(settings, DETECTOR_NORMALIZATION)) {
    detectCanonicalCollisions(entities, pairs);
    detectTaxonomyPairs(entities, pairs);
    drafts.push(...detectMissingAliases(entities, focusIds));
  }
  if (isEnabled(settings, DETECTOR_SIMILARITY)) {
    detectTrigramPairs(entities, settings.similarity_threshold, pairs);
    if (settings.description_similarity_enabled) {
      detectDescriptionPairs(entities, settings.description_similarity_threshold, pairs);
    }
  }
  const behaviorEnabled = isEnabled(settings, DETECTOR_BEHAVIOR);
  const behaviorIds = behaviorEnabled ? entities.filter((entity) => BEHAVIOR_TYPES.includes(entity.entity_type)).map((entity) => entity.internal_id) : [];
  const neighbors = behaviorIds.length > 0 ? await loadNeighborSets(context, behaviorIds) : undefined;
  if (behaviorEnabled && neighbors) {
    detectBehaviorPairs(entities, neighbors, settings.behavior_threshold, pairs);
  }
  const relevantPairs = [...pairs.values()].filter((signals) => !focusIds || focusIds.has(signals.left.internal_id) || focusIds.has(signals.right.internal_id));
  const graphSimilarity = await loadGraphSimilarity(context, R.uniq(relevantPairs.flatMap((signals) => [signals.left.internal_id, signals.right.internal_id])));
  const entitiesById = new Map(entities.map((entity) => [entity.internal_id, entity]));
  const pairDrafts: ProposalDraft[] = [];
  for (let index = 0; index < relevantPairs.length; index += 1) {
    const draft = buildPairDraft(relevantPairs[index], {
      neighbors: behaviorEnabled ? neighbors : undefined,
      graphSimilarity,
      minConfidence: settings.proposal_min_confidence,
      behaviorThreshold: settings.behavior_threshold,
    });
    if (draft) pairDrafts.push(draft);
  }
  const mergeDrafts = pairDrafts.filter((draft) => draft.kind === PROPOSAL_KIND_MERGE);
  const relationshipCounts = await countRelationshipsByEntity(context, mergeDrafts.flatMap((draft) => draft.subjects.map((subject) => subject.id)));
  mergeDrafts.forEach((draft) => {
    const candidates = draft.subjects.map((subject) => ({
      id: subject.id,
      relationships: relationshipCounts.get(subject.id) ?? 0,
      names: entitiesById.get(subject.id)?.names.length ?? 0,
    }));
    draft.target_id = selectMergeTarget(candidates) ?? draft.subjects[0].id;
  });
  drafts.push(...pairDrafts);
  return drafts;
};

const SEARCHED_PER_SCAN = 500;
const SEARCH_BATCH = 50;

/**
 * Entities loaded in different slices are never compared with each other: each scan also compares a rotating page
 * of every type with the whole graph, through the full text search candidates of the live detection, so two old
 * duplicates far apart in creation order are found over successive scans.
 */
const searchRotatingPage = async (context: AuthContext, settings: CurationSettings, types: string[], stats: ScanStats) => {
  for (let index = 0; index < types.length; index += 1) {
    const type = types[index];
    const page = await loadRotatingPage(`duplicates_search_${type}`, (after) => pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, [type], {
      first: SEARCHED_PER_SCAN,
      after,
      orderBy: 'created_at',
      orderMode: 'asc',
      baseData: true,
    } as any));
    const batches = R.splitEvery(SEARCH_BATCH, page.map((element) => element.internal_id));
    for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
      const searched = await runIncrementalDuplicateDetection(context, settings, batches[batchIndex]);
      stats.scanned += searched.scanned;
      stats.drafts += searched.drafts;
      stats.created += searched.created;
      stats.suppressed += searched.suppressed;
    }
  }
};

const familyTypesOf = (settings: CurationSettings, entityType: string) => {
  const family = getTaxonomyFamily(entityType);
  return family ? settings.curated_entity_types.filter((type) => getTaxonomyFamily(type) === family) : [entityType];
};

/**
 * A bounded scan only knows the names of the entities it loaded: the aliases it proposes are looked up in the whole
 * graph, and the proposals of the entities whose aliases another entity holds are built again knowing those owners, as
 * the incremental detection does with the owners of the taxonomy synonyms.
 */
export const checkAliasOwnership = async (context: AuthContext, settings: CurationSettings, entities: CuratedEntity[], drafts: ProposalDraft[]) => {
  const aliasDrafts = drafts.filter((draft) => draft.kind === PROPOSAL_KIND_ALIAS);
  if (aliasDrafts.length === 0) return drafts;
  const ids = R.uniq(aliasDrafts.flatMap((draft) => {
    const aliases = (draft.action_payload?.aliases ?? []) as string[];
    return familyTypesOf(settings, draft.subjects[0].entity_type).flatMap((type) => generateAliasesId(aliases, { entity_type: type }) as string[]);
  }));
  const loadedIds = new Set(entities.map((entity) => entity.internal_id));
  const curatedTypes = new Set(settings.curated_entity_types);
  const outsideOwners: CuratedEntity[] = [];
  const chunks = R.splitEvery(ID_CHUNK, ids);
  for (let index = 0; index < chunks.length; index += 1) {
    const owners = await internalFindByIds(context, CURATION_MANAGER_USER, chunks[index]) as Array<BasicStoreEntity & Record<string, any>>;
    owners.filter((owner) => curatedTypes.has(owner.entity_type) && !loadedIds.has(owner.internal_id)).forEach((owner) => {
      loadedIds.add(owner.internal_id);
      outsideOwners.push(toCuratedEntity(toCandidate(owner)));
    });
  }
  if (outsideOwners.length === 0) return drafts;
  const subjectIds = new Set(aliasDrafts.map((draft) => draft.subjects[0].id));
  const rebuilt = detectMissingAliases([...entities, ...outsideOwners], subjectIds);
  return [...drafts.filter((draft) => draft.kind !== PROPOSAL_KIND_ALIAS), ...rebuilt];
};

export const runDuplicateScan = async (context: AuthContext, settings: CurationSettings): Promise<ScanStats> => {
  const stats = emptyStats();
  if (!isDuplicateDetectionEnabled(settings)) return stats;
  const groups = scanGroups(settings.curated_entity_types.filter((type) => type !== ENTITY_TYPE_INDICATOR));
  for (let index = 0; index < groups.length; index += 1) {
    const entities = await loadCuratedEntities(context, groups[index], settings.scan_max_entities_per_type);
    stats.scanned += entities.length;
    const drafts = await detectDuplicateDrafts(context, settings, entities);
    await persistDrafts(context, settings, await checkAliasOwnership(context, settings, entities, drafts), stats);
    await searchRotatingPage(context, settings, groups[index], stats);
  }
  return stats;
};

const MAX_INCREMENTAL_CANDIDATES = 50;
const MAX_TAXONOMY_SYNONYMS = 100;

/**
 * The entities of these types named, or aliased, by a name the vendor taxonomy lists with one of the entity names: a
 * synonym can share no word with them ("Cozy Bear" for APT29), so a full text search on the entity names misses it.
 */
const findTaxonomySynonymOwners = async (context: AuthContext, entity: CuratedEntity, types: string[]) => {
  const family = getTaxonomyFamily(entity.entity_type);
  if (!family) return [];
  const own = new Set(entity.names.map((name) => name.toLowerCase()));
  const synonyms = R.uniq(findTaxonomyClusters(entity.canonicals.full, family).flatMap((cluster) => cluster.names))
    .filter((name) => !own.has(name.toLowerCase()))
    .slice(0, MAX_TAXONOMY_SYNONYMS);
  if (synonyms.length === 0) return [];
  const ids = R.uniq(types.flatMap((type) => generateAliasesId(synonyms, { entity_type: type }) as string[]));
  const owners = await internalFindByIds(context, CURATION_MANAGER_USER, ids) as Array<BasicStoreEntity & Record<string, any>>;
  return owners.filter((owner) => types.includes(owner.entity_type));
};

/**
 * Incremental duplicate detection for entities that just changed: candidates are the entities of the same family
 * found by full text search on their names, plus the owners of the names the vendor taxonomy lists for them, so the
 * missing-alias check never takes a name another entity holds for an unowned one.
 */
export const runIncrementalDuplicateDetection = async (context: AuthContext, settings: CurationSettings, entityIds: string[]): Promise<ScanStats> => {
  const stats = emptyStats();
  if (entityIds.length === 0 || !isDuplicateDetectionEnabled(settings)) return stats;
  const changed = await internalFindByIds(context, CURATION_MANAGER_USER, entityIds) as Array<BasicStoreEntity & Record<string, any>>;
  const curated = changed.filter((entity) => settings.curated_entity_types.includes(entity.entity_type) && entity.entity_type !== ENTITY_TYPE_INDICATOR);
  for (let index = 0; index < curated.length; index += 1) {
    const entity = toCuratedEntity(toCandidate(curated[index]));
    const types = familyTypesOf(settings, entity.entity_type);
    const candidates = new Map<string, CuratedEntity>([[entity.internal_id, entity]]);
    const searchTerms = R.uniq(entity.names).slice(0, 5);
    for (let termIndex = 0; termIndex < searchTerms.length; termIndex += 1) {
      const page = await pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, types, { search: searchTerms[termIndex], first: MAX_INCREMENTAL_CANDIDATES });
      page.edges.forEach(({ node }) => {
        if (!candidates.has(node.internal_id)) candidates.set(node.internal_id, toCuratedEntity(toCandidate(node as BasicStoreEntity & Record<string, any>)));
      });
    }
    const synonymOwners = await findTaxonomySynonymOwners(context, entity, types);
    synonymOwners.forEach((owner) => {
      if (!candidates.has(owner.internal_id)) candidates.set(owner.internal_id, toCuratedEntity(toCandidate(owner)));
    });
    stats.scanned += candidates.size;
    const drafts = await detectDuplicateDrafts(context, settings, [...candidates.values()], new Set([entity.internal_id]));
    await persistDrafts(context, settings, drafts, stats);
  }
  return stats;
};

/**
 * The confidence the duplicate detectors give the subjects of a merge proposal as they are now, or null when they no
 * longer find them duplicates: the entities may have been renamed or changed since the proposal was raised.
 */
export const currentMergeConfidence = async (
  context: AuthContext,
  settings: CurationSettings,
  proposal: Pick<BasicStoreEntityCurationProposal, 'subject_ids'>,
): Promise<number | null> => {
  const subjectIds = new Set(proposal.subject_ids);
  const subjects = await internalFindByIds(context, CURATION_MANAGER_USER, [...subjectIds]) as Array<BasicStoreEntity & Record<string, any>>;
  if (subjects.length !== subjectIds.size) return null;
  const entities = subjects.map((subject) => toCuratedEntity(toCandidate(subject)));
  const drafts = await detectDuplicateDrafts(context, settings, entities, subjectIds);
  const found = drafts.find((draft) => draft.kind === PROPOSAL_KIND_MERGE
    && draft.subjects.length === subjectIds.size
    && draft.subjects.every((subject) => subjectIds.has(subject.id)));
  return found ? found.confidence : null;
};
// endregion

// region contradictions (detector 4)
const DATED_FIELDS: Array<{ types: string[]; start: string; stop: string }> = [
  { types: [ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_MALWARE, ENTITY_TYPE_THREAT_ACTOR_GROUP, ENTITY_TYPE_THREAT_ACTOR_INDIVIDUAL, ENTITY_TYPE_INFRASTRUCTURE], start: 'first_seen', stop: 'last_seen' },
  { types: [ENTITY_TYPE_INDICATOR], start: 'valid_from', stop: 'valid_until' },
];

const inversionScript = (start: string, stop: string) => `doc.containsKey('${start}') && doc.containsKey('${stop}') && doc['${start}'].size() > 0 && doc['${stop}'].size() > 0`
  + ` && doc['${start}'].value.toInstant().toEpochMilli() > doc['${stop}'].value.toInstant().toEpochMilli()`;

export const findDateInversionDrafts = async (context: AuthContext): Promise<ProposalDraft[]> => {
  const drafts: ProposalDraft[] = [];
  for (let index = 0; index < DATED_FIELDS.length; index += 1) {
    const { types, start, stop } = DATED_FIELDS[index];
    const elements = await loadRotatingPage(`contradiction_${start}_${stop}`, (after) => pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, types, {
      first: MAX_CONTRADICTIONS_PER_TYPE,
      after,
      orderBy: 'created_at',
      orderMode: 'asc',
      internalScriptFilters: [inversionScript(start, stop)],
    } as any));
    elements.forEach((element) => {
      const record = element as Record<string, any>;
      drafts.push(buildDateInversionDraft({
        internal_id: element.internal_id,
        entity_type: element.entity_type,
        name: element.name ?? record.pattern ?? element.standard_id,
        start_field: start,
        stop_field: stop,
        start: new Date(record[start]).toISOString(),
        stop: new Date(record[stop]).toISOString(),
      }));
    });
  }
  const relationships = await loadRotatingPage('contradiction_relationships', (after) => pageRelationsConnection<BasicStoreRelation>(context, CURATION_MANAGER_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, {
    first: MAX_CONTRADICTIONS_PER_TYPE,
    after,
    orderBy: 'created_at',
    orderMode: 'asc',
    internalScriptFilters: [inversionScript('start_time', 'stop_time')],
    indices: READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED,
  } as any));
  relationships.forEach((relationship) => {
    const record = relationship as Record<string, any>;
    drafts.push(buildDateInversionDraft({
      internal_id: relationship.internal_id,
      entity_type: relationship.entity_type,
      name: `${record.fromName ?? relationship.fromId} ${relationship.entity_type} ${record.toName ?? relationship.toId}`,
      start_field: 'start_time',
      stop_field: 'stop_time',
      start: new Date(record.start_time).toISOString(),
      stop: new Date(record.stop_time).toISOString(),
    }));
  });
  return drafts;
};

/**
 * Pairs of entities decided distinct: rejected duplicate proposals (analyst or adjudication decision), a rotating
 * page of them per scan (see loadRotatingPage) so that every pair is checked over successive scans.
 */
const loadDistinctPairs = async (context: AuthContext) => {
  const rejected = await loadRotatingPage('distinct_pairs', (after) => pageEntitiesConnection<BasicStoreEntityCurationProposal>(context, SYSTEM_USER, [ENTITY_TYPE_CURATION_PROPOSAL], {
    first: MAX_DISTINCT_PAIRS,
    after,
    orderBy: 'created_at',
    orderMode: 'asc',
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['proposal_kind'], values: [PROPOSAL_KIND_MERGE, PROPOSAL_KIND_TYPE_MISMATCH], operator: FilterOperator.Eq },
        { key: ['proposal_status'], values: [PROPOSAL_STATUS_REJECTED], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  } as any));
  return rejected.map((proposal) => proposal.subject_ids.slice(0, 2)).filter((ids) => ids.length === 2);
};

const authorOf = (relation: BasicStoreRelation): string | null => {
  const ref = (relation as Record<string, any>)[RELATION_CREATED_BY];
  const id = Array.isArray(ref) ? ref[0] : ref;
  return typeof id === 'string' && id.length > 0 ? id : null;
};

interface Attribution { actor: string; relationship: string; author: string | null }

const authorsOf = (attributions: Attribution[], actor: string) => new Set(
  attributions.filter((item) => item.actor === actor && item.author).map((item) => item.author as string),
);

/**
 * Distinct actors can share an attribution: only sources that disagree make it a conflict, each attributing the
 * object to one of the two actors and none to both. An attribution without an author is no evidence either way.
 */
const sourcesDisagree = (attributions: Attribution[], left: string, right: string) => {
  const leftAuthors = authorsOf(attributions, left);
  const rightAuthors = authorsOf(attributions, right);
  return leftAuthors.size > 0 && rightAuthors.size > 0 && ![...leftAuthors].some((author) => rightAuthors.has(author));
};

export const findAttributionConflictDrafts = async (context: AuthContext): Promise<ProposalDraft[]> => {
  const distinctPairs = await loadDistinctPairs(context);
  if (distinctPairs.length === 0) return [];
  const actorIds = R.uniq(distinctPairs.flat());
  const attributions = new Map<string, Attribution[]>();
  const chunks = R.splitEvery(ID_CHUNK, actorIds);
  for (let index = 0; index < chunks.length; index += 1) {
    await fullRelationsList<BasicStoreRelation>(context, CURATION_MANAGER_USER, RELATION_ATTRIBUTED_TO, {
      toId: chunks[index],
      baseData: true,
      callback: async (relations: BasicStoreRelation[]) => {
        relations.forEach((relation) => {
          const list = attributions.get(relation.fromId) ?? [];
          list.push({ actor: relation.toId, relationship: relation.internal_id, author: authorOf(relation) });
          attributions.set(relation.fromId, list);
        });
      },
    });
  }
  const distinctKeys = new Set(distinctPairs.map(([left, right]) => pairKey(left, right)));
  const conflicts: Array<{ attributedId: string; actors: Attribution[] }> = [];
  attributions.forEach((list, attributedId) => {
    // One proposal per pair decided distinct: resolving it only ever removes an attribution of that pair.
    const actors = R.uniq(list.map((item) => item.actor));
    for (let left = 0; left < actors.length; left += 1) {
      for (let right = left + 1; right < actors.length; right += 1) {
        if (distinctKeys.has(pairKey(actors[left], actors[right])) && sourcesDisagree(list, actors[left], actors[right])) {
          conflicts.push({ attributedId, actors: list.filter((item) => item.actor === actors[left] || item.actor === actors[right]) });
        }
      }
    }
  });
  if (conflicts.length === 0) return [];
  // The authors decide the conflict but are not named in it: a reader of the proposal may not be allowed to read them.
  const ids = R.uniq(conflicts.flatMap((conflict) => [conflict.attributedId, ...conflict.actors.map((item) => item.actor)]));
  const elements = await internalFindByIds(context, CURATION_MANAGER_USER, ids, { toMap: true, baseData: true, baseFields: ['name'] }) as unknown as Record<string, BasicStoreEntity>;
  return conflicts
    .filter((conflict) => elements[conflict.attributedId] && conflict.actors.every((item) => elements[item.actor]))
    .map((conflict) => buildAttributionConflictDraft({
      attributed: { id: conflict.attributedId, entity_type: elements[conflict.attributedId].entity_type, name: elements[conflict.attributedId].name },
      actors: conflict.actors.map((item) => ({
        id: item.actor,
        entity_type: elements[item.actor].entity_type,
        name: elements[item.actor].name,
        relationship_id: item.relationship,
      })),
    }));
};

export const findRevokedIndicatorDrafts = async (context: AuthContext): Promise<ProposalDraft[]> => {
  const indicators = await loadRotatingPage('contradiction_revoked_indicators', (after) => pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, [ENTITY_TYPE_INDICATOR], {
    filters: { mode: FilterMode.And, filters: [{ key: ['revoked'], values: ['true'], operator: FilterOperator.Eq }], filterGroups: [] },
    first: MAX_REVOKED_INDICATORS,
    after,
    orderBy: 'created_at',
    orderMode: 'asc',
  } as any));
  if (indicators.length === 0) return [];
  const basedOn = new Map<string, string[]>();
  const chunks = R.splitEvery(ID_CHUNK, indicators.map((indicator) => indicator.internal_id));
  for (let index = 0; index < chunks.length; index += 1) {
    await fullRelationsList<BasicStoreRelation>(context, CURATION_MANAGER_USER, RELATION_BASED_ON, {
      fromId: chunks[index],
      baseData: true,
      callback: async (relations: BasicStoreRelation[]) => {
        relations.forEach((relation) => basedOn.set(relation.fromId, [...(basedOn.get(relation.fromId) ?? []), relation.toId]));
      },
    });
  }
  const observableIds = R.uniq([...basedOn.values()].flat());
  if (observableIds.length === 0) return [];
  const observables = await internalFindByIds(context, CURATION_MANAGER_USER, observableIds, { toMap: true }) as unknown as Record<string, BasicStoreEntity & Record<string, any>>;
  const drafts: ProposalDraft[] = [];
  indicators.forEach((indicator) => {
    const record = indicator as Record<string, any>;
    const active = observablesActiveSinceRevocation(record, (basedOn.get(indicator.internal_id) ?? []).map((id) => observables[id]));
    if (active.length > 0) {
      drafts.push(buildRevokedIndicatorDraft({
        indicator: { id: indicator.internal_id, name: indicator.name ?? record.pattern, valid_until: record.valid_until ?? null },
        observables: active.map((observable) => ({
          id: observable.internal_id,
          entity_type: observable.entity_type,
          name: observable.observable_value ?? observable.name ?? observable.standard_id,
          last_activity: new Date(observable.updated_at).toISOString(),
          score: observable.x_opencti_score ?? null,
        })),
      }));
    }
  });
  return drafts;
};

const addSplitDrafts = async (context: AuthContext, drafts: ProposalDraft[]) => {
  const contradictionDrafts = drafts.filter((draft) => draft.kind === PROPOSAL_KIND_CONTRADICTION);
  const subjectIds = R.uniq(contradictionDrafts.flatMap((draft) => draft.subjects.map((subject) => subject.id)));
  if (subjectIds.length === 0) return [];
  const records = await fullEntitiesList<BasicStoreEntityMergeRecord>(context, SYSTEM_USER, [ENTITY_TYPE_MERGE_RECORD], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['merge_target_id'], values: subjectIds, operator: FilterOperator.Eq },
        { key: ['merge_status'], values: [MERGE_STATUS_ACTIVE, MERGE_STATUS_PARTIALLY_REVERTED], operator: FilterOperator.Eq },
      ],
      filterGroups: [],
    },
  });
  const splits: ProposalDraft[] = [];
  records.forEach((record) => {
    const contradiction = contradictionDrafts.find((draft) => draft.subjects.some((subject) => subject.id === record.merge_target_id));
    if (!contradiction) return;
    const subject = contradiction.subjects.find((s) => s.id === record.merge_target_id);
    if (!subject) return;
    splits.push(buildSplitDraft(subject, { id: record.internal_id, source_names: record.merge_source_names }, contradiction.evidence[0]));
  });
  return splits;
};

export const runContradictionScan = async (context: AuthContext, settings: CurationSettings): Promise<ScanStats> => {
  const stats = emptyStats();
  if (!isEnabled(settings, DETECTOR_CONTRADICTION)) return stats;
  const drafts = [
    ...(await findDateInversionDrafts(context)),
    ...(await findAttributionConflictDrafts(context)),
    ...(await findRevokedIndicatorDrafts(context)),
  ];
  drafts.push(...(await addSplitDrafts(context, drafts)));
  stats.scanned = drafts.length;
  await persistDrafts(context, settings, drafts, stats);
  return stats;
};
// endregion

// region staleness (detector 5)
export const runStalenessScan = async (context: AuthContext, settings: CurationSettings): Promise<ScanStats> => {
  const stats = emptyStats();
  if (!isEnabled(settings, DETECTOR_STALENESS)) return stats;
  const types = R.uniq([...settings.curated_entity_types, ENTITY_TYPE_INDICATOR]);
  const drafts: ProposalDraft[] = [];
  for (let index = 0; index < types.length; index += 1) {
    const type = types[index];
    const months = getStalenessMonths(settings, type);
    const cutoff = new Date(Date.now() - months * 30 * 24 * 3600 * 1000).toISOString();
    const candidates = await loadRotatingPage(`staleness_${type}`, (after) => pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, [type], {
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['updated_at'], values: [cutoff], operator: FilterOperator.Lt },
          { key: ['revoked'], values: ['false'], operator: FilterOperator.Eq },
        ],
        filterGroups: [],
      },
      first: MAX_STALE_PER_TYPE,
      after,
      orderBy: 'updated_at',
      orderMode: 'asc',
    } as any));
    stats.scanned += candidates.length;
    if (candidates.length === 0) continue;
    // Entities with a relationship created or updated after the cutoff are still alive.
    const alive = new Set<string>();
    const chunks = R.splitEvery(ID_CHUNK, candidates.map((candidate) => candidate.internal_id));
    for (let chunkIndex = 0; chunkIndex < chunks.length; chunkIndex += 1) {
      const chunkSet = new Set(chunks[chunkIndex]);
      await fullRelationsList<BasicStoreRelation>(context, CURATION_MANAGER_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, {
        fromOrToId: chunks[chunkIndex],
        filters: { mode: FilterMode.And, filters: [{ key: ['updated_at'], values: [cutoff], operator: FilterOperator.Gte }], filterGroups: [] },
        baseData: true,
        callback: async (relations: BasicStoreRelation[]) => {
          relations.forEach((relation) => {
            if (chunkSet.has(relation.fromId)) alive.add(relation.fromId);
            if (chunkSet.has(relation.toId)) alive.add(relation.toId);
          });
        },
      });
    }
    candidates.filter((candidate) => !alive.has(candidate.internal_id)).forEach((candidate) => {
      const record = candidate as Record<string, any>;
      drafts.push(buildStaleDraft({
        internal_id: candidate.internal_id,
        entity_type: candidate.entity_type,
        name: candidate.name ?? record.pattern ?? candidate.standard_id,
        last_activity: new Date(record.updated_at).toISOString(),
        months,
        revoked: false,
        decayed: null,
      }));
    });
  }
  // Decayed indicators: live score at or below the revoke score of their decay rule (the decay manager revokes there
  // too), still not revoked. The decay rule is a flattened attribute, so the comparison is done here, page by page.
  const decayCandidates = await loadRotatingPage('staleness_decayed_indicators', (after) => pageEntitiesConnection<BasicStoreEntity>(context, CURATION_MANAGER_USER, [ENTITY_TYPE_INDICATOR], {
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['revoked'], values: ['false'], operator: FilterOperator.Eq },
        { key: ['decay_base_score'], values: [], operator: FilterOperator.NotNil },
      ],
      filterGroups: [],
    },
    first: MAX_STALE_PER_TYPE,
    after,
    orderBy: 'created_at',
    orderMode: 'asc',
    noFiltersChecking: true,
  } as any));
  const decayed = decayCandidates.filter((indicator) => isDecayedToRevocation(indicator as Record<string, any>));
  decayed.forEach((indicator) => {
    const record = indicator as Record<string, any>;
    if (drafts.some((draft) => draft.subjects[0].id === indicator.internal_id)) return;
    drafts.push(buildStaleDraft({
      internal_id: indicator.internal_id,
      entity_type: indicator.entity_type,
      name: indicator.name ?? record.pattern ?? indicator.standard_id,
      last_activity: new Date(record.updated_at).toISOString(),
      months: getStalenessMonths(settings, ENTITY_TYPE_INDICATOR),
      revoked: false,
      decayed: { score: record.x_opencti_score, revoke_score: record.decay_applied_rule?.decay_revoke_score },
    }));
  });
  await persistDrafts(context, settings, drafts, stats);
  return stats;
};
// endregion
