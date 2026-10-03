/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { createHash } from 'node:crypto';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import type { BasicStoreSettings } from '../../types/settings';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { createEntity, deleteElementById, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, internalFindByIds, pageEntitiesConnection } from '../../database/middleware-loader';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import { elCount, elPaginate } from '../../database/engine';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { logApp } from '../../config/conf';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import { SOURCE_INTELLIGENCE_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_CONTAINER_REPORT,
  ENTITY_TYPE_IDENTITY_SECTOR,
  ENTITY_TYPE_INTRUSION_SET,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_POSITION,
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_MALWARE,
  ENTITY_TYPE_THREAT_ACTOR_GROUP,
} from '../../schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../administrativeArea/administrativeArea-types';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { type BasicStoreEntityPir, ENTITY_TYPE_PIR } from '../pir/pir-types';
import { constructFinalPirFilters, parsePir } from '../pir/pir-utils';
import { getPirWithAccessCheck } from '../pir/pir-checkPirAccess';
import { findPirPaginated } from '../pir/pir-domain';
import { type FilterGroup, PirType } from '../../generated/graphql';
import { type BasicStoreEntityCatalogContract, ENTITY_TYPE_CATALOG_CONTRACT } from '../catalog/catalog-types';
import { type HubIntegrationCoverageMatch, xtmHubClient } from '../xtm/hub/xtm-hub-client';
import type { SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
  type BasicStoreEntityCollectionGap,
  type BasicStoreEntitySource,
  type CollectionGapRecommendedConnector,
  ENTITY_TYPE_COLLECTION_GAP,
  type HubCatalogStatus,
  RECOMMENDATION_ADD_CONNECTOR,
} from './sourceIntelligence-types';
import { buildResolverFromSources } from './sourceIntelligence-domain';
import { resolveDocumentAssertions } from './sourceIntelligence-provenance';
import { round } from './sourceIntelligence-scoring';
import { recommendationFingerprint, type RecommendationProposal } from './sourceIntelligence-rules';
import { applyAutonomousRecommendations, upsertProposals } from './sourceIntelligence-recommendations';

const DAY_MS = 24 * 3600 * 1000;
const COVERAGE_SAMPLE_SIZE = 2000;
const MAX_COVERING_SOURCES = 10;
const LOCAL_CATALOG_WEIGHT = 0.6;
const RELATION_TO_FILTER_KEY = 'toId';
const RELATION_TYPE_FILTER_KEYS = ['relationship_type'];
const REGION_TYPES = [
  ENTITY_TYPE_LOCATION_REGION,
  ENTITY_TYPE_LOCATION_COUNTRY,
  ENTITY_TYPE_LOCATION_CITY,
  ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA,
  ENTITY_TYPE_LOCATION_POSITION,
];
const THREAT_TYPES = [ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_MALWARE, ENTITY_TYPE_CAMPAIGN, ENTITY_TYPE_THREAT_ACTOR_GROUP];
const HUB_INTEGRATION_TYPES = ['connector', 'taxii_feed', 'rss_feed', 'csv_feed', 'stream'];

// Deterministic keywords used to match the local catalog when XTM Hub is not available
export const OBJECT_TYPE_KEYWORDS: Array<[string, RegExp]> = [
  [ENTITY_TYPE_INDICATOR, /\b(indicators?|iocs?)\b/],
  [ENTITY_TYPE_MALWARE, /\bmalwares?\b|ransomware|botnets?|trojans?/],
  ['Vulnerability', /vulnerabilit|\bcves?\b|exploits?/],
  [ENTITY_TYPE_INTRUSION_SET, /\bapts?\b|intrusion sets?|threat actors?|adversar/],
  [ENTITY_TYPE_THREAT_ACTOR_GROUP, /threat actors?|adversar|threat groups?/],
  [ENTITY_TYPE_CAMPAIGN, /campaigns?/],
  ['Attack-Pattern', /att&ck|\bttps?\b|techniques?|attack patterns?/],
  [ENTITY_TYPE_CONTAINER_REPORT, /\breports?\b|advisor|bulletins?|blog/],
  ['IPv4-Addr', /\bips?\b|ip address|ipv4/],
  ['Domain-Name', /\bdomains?\b|\bdns\b/],
  ['Url', /\burls?\b|phishing/],
  ['StixFile', /\bhash(es)?\b|\bfiles?\b|samples?/],
  ['Email-Addr', /e-?mails?|phishing/],
];

// region facets extraction
export interface CriterionFacets {
  targetIds: string[];
  relationshipTypes: string[];
  fromTypes: string[];
}

export const extractCriterionFacets = (filterGroup: FilterGroup | null | undefined): CriterionFacets => {
  const facets: CriterionFacets = { targetIds: [], relationshipTypes: [], fromTypes: [] };
  const visit = (group: FilterGroup | null | undefined) => {
    if (!group) return;
    (group.filters ?? []).forEach((filter) => {
      const keys = Array.isArray(filter.key) ? filter.key : [filter.key];
      const values = (filter.values ?? []).filter((v): v is string => typeof v === 'string');
      if (keys.includes(RELATION_TO_FILTER_KEY)) facets.targetIds.push(...values);
      if (keys.some((key) => RELATION_TYPE_FILTER_KEYS.includes(key))) facets.relationshipTypes.push(...values);
      if (keys.includes('fromTypes')) facets.fromTypes.push(...values);
    });
    (group.filterGroups ?? []).forEach(visit);
  };
  visit(filterGroup);
  return {
    targetIds: [...new Set(facets.targetIds)],
    relationshipTypes: [...new Set(facets.relationshipTypes)],
    fromTypes: [...new Set(facets.fromTypes)],
  };
};

export interface ResolvedFacets {
  objectTypes: string[];
  sectors: string[];
  regions: string[];
  label: string;
}

export const resolveFacets = (pirType: string, facets: CriterionFacets, targets: Array<{ entity_type: string; name: string }>): ResolvedFacets => {
  const sectors = targets.filter((t) => t.entity_type === ENTITY_TYPE_IDENTITY_SECTOR).map((t) => t.name);
  const regions = targets.filter((t) => REGION_TYPES.includes(t.entity_type)).map((t) => t.name);
  const otherTargetTypes = targets.filter((t) => t.entity_type !== ENTITY_TYPE_IDENTITY_SECTOR && !REGION_TYPES.includes(t.entity_type)).map((t) => t.entity_type);
  const threatTypes = facets.fromTypes.length > 0 ? facets.fromTypes : (pirType === PirType.ThreatLandscape || pirType === PirType.ThreatOrigin ? THREAT_TYPES : []);
  const objectTypes = [...new Set([...threatTypes, ...otherTargetTypes, ENTITY_TYPE_INDICATOR])];
  const relation = facets.relationshipTypes.length > 0 ? facets.relationshipTypes.join(', ') : 'related to';
  const names = targets.map((t) => t.name);
  const label = names.length > 0 ? `${relation} ${names.join(', ')}` : relation;
  return { objectTypes, sectors: [...new Set(sectors)], regions: [...new Set(regions)], label };
};

export const criterionKey = (filters: string) => createHash('sha256').update(filters).digest('hex').substring(0, 32);
// endregion

// region coverage
export const computeGapCoverageScore = (input: { recent: number; window: number; distinctSources: number }, settings: SourceIntelligenceSettings['gaps']) => {
  const volume = Math.min(1, input.recent / settings.target_relationships);
  const diversity = Math.min(1, input.distinctSources / settings.target_sources);
  const freshness = input.window > 0 ? Math.min(1, input.recent / input.window) : 0;
  return Math.round(100 * (0.4 * volume + 0.4 * diversity + 0.2 * freshness));
};

const countMatchingRelationships = async (context: AuthContext, filters: FilterGroup, sinceDays: number) => {
  const since = new Date(Date.now() - sinceDays * DAY_MS).toISOString();
  return elCount(context, SYSTEM_USER, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
    types: [ABSTRACT_STIX_CORE_RELATIONSHIP],
    filters: {
      mode: 'and',
      filters: [{ key: ['updated_at'], values: [since], operator: 'gte', mode: 'or' }],
      filterGroups: [filters],
    },
  });
};

const sampleCoveringSources = async (context: AuthContext, filters: FilterGroup, sinceDays: number, sources: BasicStoreEntitySource[]) => {
  const since = new Date(Date.now() - sinceDays * DAY_MS).toISOString();
  const relationships = await elPaginate<BasicStoreEntity>(context, SYSTEM_USER, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
    types: [ABSTRACT_STIX_CORE_RELATIONSHIP],
    first: COVERAGE_SAMPLE_SIZE,
    orderBy: 'updated_at',
    orderMode: 'desc',
    connectionFormat: false,
    filters: {
      mode: 'and',
      filters: [{ key: ['updated_at'], values: [since], operator: 'gte', mode: 'or' }],
      filterGroups: [filters],
    },
  } as any) as unknown as Array<BasicStoreEntity & Record<string, any>>;
  const resolver = buildResolverFromSources(sources);
  const counts = new Map<string, number>();
  relationships.forEach((relationship) => {
    const assertions = resolveDocumentAssertions({
      internal_id: relationship.internal_id,
      created_at: relationship.created_at as unknown as string,
      updated_at: relationship.updated_at as unknown as string,
      creator_id: relationship.creator_id,
      'rel_created-by.internal_id': relationship['created-by'] ? [relationship['created-by']] : [],
      x_opencti_assertions: relationship.x_opencti_assertions,
    }, resolver);
    assertions.forEach((assertion) => counts.set(assertion.sourceId, (counts.get(assertion.sourceId) ?? 0) + 1));
  });
  const total = relationships.length;
  const covering = Array.from(counts.entries())
    .map(([source_id, matched_count]) => ({ source_id, matched_count, share: total > 0 ? round(matched_count / total) : 0 }))
    .sort((a, b) => b.matched_count - a.matched_count);
  return { covering: covering.slice(0, MAX_COVERING_SOURCES), distinct: covering.length };
};
// endregion

// region catalog matching
const matchValues = (requested: string[], text: string) => {
  return requested.filter((value) => {
    const escaped = value.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b${escaped}\\b`).test(text);
  });
};

const familyScore = (requested: string[], matched: string[]) => (requested.length > 0 ? matched.length / requested.length : null);

export const scoreCoverageMatch = (facets: ResolvedFacets, matched: { objectTypes: string[]; sectors: string[]; regions: string[] }, weight: number) => {
  const families = [
    familyScore(facets.objectTypes, matched.objectTypes),
    familyScore(facets.sectors, matched.sectors),
    familyScore(facets.regions, matched.regions),
  ].filter((value): value is number => value !== null);
  if (families.length === 0) return 0;
  return round(weight * (families.reduce((acc, value) => acc + value, 0) / families.length));
};

export const matchLocalCatalog = (facets: ResolvedFacets, contracts: BasicStoreEntityCatalogContract[]): CollectionGapRecommendedConnector[] => {
  const latestBySlug = new Map<string, BasicStoreEntityCatalogContract>();
  contracts.forEach((contract) => {
    const current = latestBySlug.get(contract.slug);
    if (!current || (contract.contract_version ?? '') > (current.contract_version ?? '')) latestBySlug.set(contract.slug, contract);
  });
  const results: CollectionGapRecommendedConnector[] = [];
  latestBySlug.forEach((contract) => {
    const text = [contract.title, contract.short_description, contract.description, ...(contract.use_cases ?? []), ...(contract.solution_categories ?? [])]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    const matchedObjectTypes = facets.objectTypes.filter((type) => OBJECT_TYPE_KEYWORDS.find(([keywordType]) => keywordType === type)?.[1].test(text));
    const matched = { objectTypes: matchedObjectTypes, sectors: matchValues(facets.sectors, text), regions: matchValues(facets.regions, text) };
    // A catalog entry must at least match the threat landscape (sector or region) when the criterion has one
    if ((facets.sectors.length > 0 || facets.regions.length > 0) && matched.sectors.length === 0 && matched.regions.length === 0) return;
    const score = scoreCoverageMatch(facets, matched, LOCAL_CATALOG_WEIGHT);
    if (score <= 0) return;
    results.push({
      slug: contract.slug,
      title: contract.title,
      short_description: contract.short_description,
      origin: 'catalog',
      score,
      catalog_id: contract.catalog_id,
      contract_image: contract.image,
      manager_supported: contract.manager_supported,
      verified: contract.verified,
      deployed: false,
      coverage_inferred: true,
      matched_object_types: matched.objectTypes,
      matched_sectors: matched.sectors,
      matched_regions: matched.regions,
    });
  });
  return results;
};

export const mergeRecommendedConnectors = (
  hubMatches: HubIntegrationCoverageMatch[],
  localMatches: CollectionGapRecommendedConnector[],
  contracts: BasicStoreEntityCatalogContract[],
  deployedImages: Set<string>,
  max: number,
): CollectionGapRecommendedConnector[] => {
  const contractBySlug = new Map(contracts.map((contract) => [contract.slug, contract]));
  const merged = new Map<string, CollectionGapRecommendedConnector>();
  hubMatches.forEach((match) => {
    const contract = contractBySlug.get(match.slug);
    merged.set(match.slug, {
      slug: match.slug,
      title: match.name,
      short_description: match.short_description,
      origin: 'hub',
      score: round(match.score),
      catalog_id: contract?.catalog_id ?? null,
      contract_image: contract?.image ?? null,
      manager_supported: contract?.manager_supported ?? match.manager_supported === true,
      verified: match.verified,
      deployed: false,
      coverage_inferred: match.coverage_inferred,
      matched_object_types: match.matched_object_types ?? [],
      matched_sectors: match.matched_sectors ?? [],
      matched_regions: match.matched_regions ?? [],
    });
  });
  localMatches.forEach((match) => {
    if (!merged.has(match.slug)) merged.set(match.slug, match);
  });
  return Array.from(merged.values())
    .map((match) => ({ ...match, deployed: match.contract_image ? deployedImages.has(match.contract_image) : false }))
    .sort((a, b) => Number(a.deployed) - Number(b.deployed) || b.score - a.score || a.title.localeCompare(b.title))
    .slice(0, max);
};
// endregion

// region computation
const hubPlatformOf = async (context: AuthContext) => {
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return settings?.xtm_hub_token ? { platformId: settings.id, platformToken: settings.xtm_hub_token } : null;
};

/**
 * Compute the collection gap of every PIR criterion: how well the platform sources cover it, and which catalog
 * integrations (XTM Hub first, local catalog otherwise) would fill it.
 */
export const computeCollectionGaps = async (context: AuthContext, sources: BasicStoreEntitySource[], settings: SourceIntelligenceSettings) => {
  const pirs = await fullEntitiesList<BasicStoreEntityPir>(context, SYSTEM_USER, [ENTITY_TYPE_PIR]);
  const existingGaps = await fullEntitiesList<BasicStoreEntityCollectionGap>(context, SYSTEM_USER, [ENTITY_TYPE_COLLECTION_GAP]);
  const existingByKey = new Map(existingGaps.map((gap) => [`${gap.pir_id}|${gap.criterion_key}`, gap]));
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(context, SYSTEM_USER, [ENTITY_TYPE_CATALOG_CONTRACT]);
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const deployedImages = new Set(connectors.map((connector) => connector.manager_contract_image).filter((image): image is string => !!image));
  const hubPlatform = await hubPlatformOf(context);
  const keptKeys = new Set<string>();
  const proposals: RecommendationProposal[] = [];
  const nowIso = new Date().toISOString();
  let gapsCount = 0;
  for (let p = 0; p < pirs.length; p += 1) {
    const pir = pirs[p];
    const parsed = parsePir(pir);
    for (let c = 0; c < parsed.pir_criteria.length; c += 1) {
      const criterion = parsed.pir_criteria[c];
      const rawFilters = pir.pir_criteria[c].filters;
      const key = criterionKey(rawFilters);
      keptKeys.add(`${pir.internal_id}|${key}`);
      const facets = extractCriterionFacets(criterion.filters);
      const targets = facets.targetIds.length > 0
        ? await internalFindByIds(context, SYSTEM_USER, facets.targetIds) as unknown as Array<BasicStoreEntity & { name: string }>
        : [];
      const resolved = resolveFacets(pir.pir_type, facets, targets);
      const finalFilters: FilterGroup = {
        mode: 'and' as FilterGroup['mode'],
        filters: [],
        filterGroups: [criterion.filters, constructFinalPirFilters(pir.pir_type, parsed.pir_filters)],
      };
      const [windowCount, recentCount, sample] = await Promise.all([
        countMatchingRelationships(context, finalFilters, settings.gaps.window_days),
        countMatchingRelationships(context, finalFilters, settings.gaps.recent_days),
        sampleCoveringSources(context, finalFilters, settings.gaps.window_days, sources),
      ]);
      const coverage = computeGapCoverageScore({ recent: recentCount, window: windowCount, distinctSources: sample.distinct }, settings.gaps);
      const isGap = coverage < settings.thresholds.gap_coverage;
      let hubStatus: HubCatalogStatus = hubPlatform ? 'ok' : 'not_registered';
      let recommended: CollectionGapRecommendedConnector[] = [];
      if (isGap) {
        let hubMatches: HubIntegrationCoverageMatch[] = [];
        if (hubPlatform) {
          const hubResult = await xtmHubClient.integrationsByCoverage(hubPlatform, {
            objectTypes: resolved.objectTypes,
            sectors: resolved.sectors,
            regions: resolved.regions,
            integrationTypes: HUB_INTEGRATION_TYPES,
            first: settings.gaps.max_recommendations * 3,
          });
          hubStatus = hubResult.status;
          hubMatches = hubResult.matches;
        }
        recommended = mergeRecommendedConnectors(hubMatches, matchLocalCatalog(resolved, contracts), contracts, deployedImages, settings.gaps.max_recommendations);
        gapsCount += 1;
      }
      const gapFields = {
        name: `${pir.name} - ${resolved.label}`,
        pir_id: pir.internal_id,
        criterion_index: c,
        criterion_key: key,
        criterion_filters: rawFilters,
        criterion_weight: criterion.weight,
        criterion_label: resolved.label,
        gap_coverage_score: coverage,
        is_gap: isGap,
        matched_relationships: windowCount,
        recent_relationships: recentCount,
        distinct_sources: sample.distinct,
        covering_sources: sample.covering,
        object_types: resolved.objectTypes,
        sectors: resolved.sectors,
        regions: resolved.regions,
        recommended_connectors: recommended,
        hub_status: hubStatus,
        computed_at: nowIso,
      };
      const existing = existingByKey.get(`${pir.internal_id}|${key}`);
      let gapId: string;
      if (existing) {
        await patchAttribute(context, SOURCE_INTELLIGENCE_MANAGER_USER, existing.internal_id, ENTITY_TYPE_COLLECTION_GAP, gapFields);
        gapId = existing.internal_id;
      } else {
        const created = await createEntity(context, SOURCE_INTELLIGENCE_MANAGER_USER, gapFields, ENTITY_TYPE_COLLECTION_GAP);
        gapId = (created as BasicStoreEntity).internal_id;
      }
      const best = recommended.find((connector) => !connector.deployed);
      if (isGap && best) {
        proposals.push({
          kind: RECOMMENDATION_ADD_CONNECTOR,
          source_id: null,
          fingerprint: recommendationFingerprint(RECOMMENDATION_ADD_CONNECTOR, pir.internal_id, key, best.slug),
          name: `Deploy ${best.title} for ${pir.name}`,
          rationale: `The criterion "${resolved.label}" of the PIR ${pir.name} has a coverage of ${coverage}/100 `
            + `(${recentCount} relationships in the last ${settings.gaps.recent_days} days from ${sample.distinct} sources). `
            + `${best.title} covers ${[...best.matched_object_types, ...best.matched_sectors, ...best.matched_regions].join(', ') || 'this criterion'}.`,
          payload: {
            pir_id: pir.internal_id,
            collection_gap_id: gapId,
            slug: best.slug,
            title: best.title,
            catalog_id: best.catalog_id,
            contract_image: best.contract_image,
            origin: best.origin,
            score: best.score,
          },
          evidence: { coverage_score: coverage, recent_relationships: recentCount, matched_relationships: windowCount, distinct_sources: sample.distinct },
        });
      }
    }
  }
  // Criteria removed from their PIR, or deleted PIRs
  const removed = existingGaps.filter((gap) => !keptKeys.has(`${gap.pir_id}|${gap.criterion_key}`));
  for (let i = 0; i < removed.length; i += 1) {
    await deleteElementById(context, SOURCE_INTELLIGENCE_MANAGER_USER, removed[i].internal_id, ENTITY_TYPE_COLLECTION_GAP);
  }
  const { created } = await upsertProposals(context, proposals, settings, { kinds: [RECOMMENDATION_ADD_CONNECTOR] });
  await applyAutonomousRecommendations(context, created, settings);
  logApp.info('[OPENCTI-MODULE] Source intelligence collection gaps computed', { pirs: pirs.length, gaps: gapsCount, removed: removed.length, proposals: proposals.length });
  return { gaps: gapsCount, proposals: proposals.length };
};
// endregion

// region queries
interface CollectionGapsArgs {
  pirId?: string | null;
  onlyGaps?: boolean | null;
  first?: number | null;
  after?: string | null;
  orderBy?: string | null;
  orderMode?: string | null;
}

export const findCollectionGaps = async (context: AuthContext, user: AuthUser, args: CollectionGapsArgs) => {
  await checkEnterpriseEdition(context);
  let pirIds: string[];
  if (args.pirId) {
    const pir = await getPirWithAccessCheck(context, user, args.pirId);
    pirIds = [pir.internal_id];
  } else {
    const pirs = await findPirPaginated(context, user, { first: 500 });
    pirIds = pirs.edges.map((edge) => edge.node.internal_id);
  }
  if (pirIds.length === 0) {
    return { edges: [], pageInfo: { startCursor: '', endCursor: '', hasNextPage: false, hasPreviousPage: false, globalCount: 0 } };
  }
  const filters: any[] = [{ key: ['pir_id'], values: pirIds, operator: 'eq', mode: 'or' }];
  if (args.onlyGaps) filters.push({ key: ['is_gap'], values: [true], operator: 'eq', mode: 'or' });
  return pageEntitiesConnection<BasicStoreEntityCollectionGap>(context, user, [ENTITY_TYPE_COLLECTION_GAP], {
    first: args.first ?? 100,
    after: args.after,
    orderBy: args.orderBy ?? 'gap_coverage_score',
    orderMode: args.orderMode ?? 'asc',
    filters: { mode: 'and', filters, filterGroups: [] },
  } as any);
};
// endregion
