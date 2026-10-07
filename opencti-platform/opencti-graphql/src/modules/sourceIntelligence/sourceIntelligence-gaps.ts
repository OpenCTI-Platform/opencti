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
import { fullEntitiesList, internalFindByIds, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import { FunctionalError, LockTimeoutError, TYPE_LOCK_ERROR } from '../../config/errors';
import { lockResources } from '../../lock/master-lock';
import { getEntitiesListFromCache, getEntityFromCache } from '../../database/cache';
import { elCount, elFilteredAggregations } from '../../database/engine';
import { READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED } from '../../database/utils';
import { logApp } from '../../config/conf';
import { checkEnterpriseEdition, isEnterpriseEdition } from '../../enterprise-edition/ee';
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
import { type ContractConfigInput, type FilterGroup, PirType } from '../../generated/graphql';
import { type BasicStoreEntityCatalogContract, ENTITY_TYPE_CATALOG_CONTRACT } from '../catalog/catalog-types';
import { compareContractVersions, isSupportVersionCompatible } from '../catalog/catalog-version-utils';
import { type HubIntegrationCoverageMatch, type HubIntegrationCoverageResult, xtmHubClient } from '../xtm/hub/xtm-hub-client';
import type { SourceIntelligenceSettings } from './sourceIntelligence-settings';
import {
  type BasicStoreEntityCollectionGap,
  type BasicStoreEntitySource,
  type CollectionGapRecommendedConnector,
  ENTITY_TYPE_COLLECTION_GAP,
  type HubCatalogStatus,
  RECOMMENDATION_ADD_CONNECTOR,
  RECOMMENDATION_STATUS_APPLIED,
  RECOMMENDATION_STATUS_REVERTING,
} from './sourceIntelligence-types';
import { buildSourceResolver, type SourceResolver, userSource } from './sourceIntelligence-provenance';
import { round } from './sourceIntelligence-scoring';
import { connectorMatchesCatalogEntry, recommendationFingerprint, type RecommendationProposal } from './sourceIntelligence-rules';
import { applySourceRecommendation, findOrCreateProposal, findRecommendationsByFingerprint, listAccessiblePirIds, upsertProposals } from './sourceIntelligence-recommendations';
import { canReadSourceIntelligence } from './sourceIntelligence-domain';

const DAY_MS = 24 * 3600 * 1000;
const COVERAGE_PAGE_SIZE = 1000;
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

type CompositeBuckets = { buckets?: Array<{ key: { id: string }; doc_count: number }>; after_key?: { id: string } };

/**
 * Number of matching relationships per value of `field`, for every value: a composite aggregation read page after page
 * (a terms aggregation would silently drop the smallest buckets above its size).
 */
export const countRelationshipsByValue = async (
  aggregate: (aggregations: Record<string, unknown>) => Promise<Record<string, any>>,
  field: string,
) => {
  const counts = new Map<string, number>();
  let after: { id: string } | undefined;
  do {
    const data = await aggregate({
      values: { composite: { size: COVERAGE_PAGE_SIZE, sources: [{ id: { terms: { field } } }], ...(after ? { after } : {}) } },
    });
    const page = data.values as CompositeBuckets | undefined;
    const buckets = page?.buckets ?? [];
    buckets.forEach((bucket) => counts.set(bucket.key.id, bucket.doc_count));
    after = buckets.length === COVERAGE_PAGE_SIZE ? page?.after_key : undefined;
  } while (after);
  return counts;
};

export interface CoveringRelationshipCounts {
  // creator user id -> relationships it created
  creators: Map<string, number>;
  // author identity id -> relationships it authored
  authors: Map<string, number>;
}

/**
 * Relationships matched per source, with the attribution of the scorecards: their creators (connector, feed and analyst
 * users) and their author.
 */
export const countCoveringRelationshipsPerSource = (resolver: SourceResolver, counts: CoveringRelationshipCounts) => {
  const perSource = new Map<string, number>();
  const add = (sourceId: string | undefined, count: number) => {
    if (sourceId && count > 0) perSource.set(sourceId, (perSource.get(sourceId) ?? 0) + count);
  };
  counts.creators.forEach((count, userId) => add(userSource(resolver, userId), count));
  counts.authors.forEach((count, authorId) => add(resolver.byAuthor.get(authorId), count));
  return perSource;
};

/**
 * Sources covering a criterion, over every matching relationship of the window (aggregations, no sampling), each
 * relationship counted once per source.
 */
const aggregateCoveringSources = async (
  context: AuthContext,
  filters: FilterGroup,
  sinceDays: number,
  sources: BasicStoreEntitySource[],
  total: number,
) => {
  const since = new Date(Date.now() - sinceDays * DAY_MS).toISOString();
  const aggregate = (aggregations: Record<string, unknown>) => {
    return elFilteredAggregations(context, SYSTEM_USER, READ_RELATIONSHIPS_INDICES_WITHOUT_INFERRED, {
      types: [ABSTRACT_STIX_CORE_RELATIONSHIP],
      filters: {
        mode: 'and',
        filters: [{ key: ['updated_at'], values: [since], operator: 'gte', mode: 'or' }],
        filterGroups: [filters],
      },
    } as any, aggregations);
  };
  const resolver = buildSourceResolver(sources);
  const counts = countCoveringRelationshipsPerSource(resolver, {
    creators: await countRelationshipsByValue(aggregate, 'creator_id.keyword'),
    authors: await countRelationshipsByValue(aggregate, 'rel_created-by.internal_id.keyword'),
  });
  const covering = Array.from(counts.entries())
    .map(([source_id, count]) => {
      const matched_count = Math.min(count, total);
      return { source_id, matched_count, share: total > 0 ? round(matched_count / total) : 0 };
    })
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

/**
 * The contract a recommendation deploys for each catalog slug: the latest version compatible with this platform, with
 * the catalog's own version ordering (semver, rolling).
 */
export const latestCompatibleContractsBySlug = (contracts: BasicStoreEntityCatalogContract[]) => {
  const latestBySlug = new Map<string, BasicStoreEntityCatalogContract>();
  contracts.filter((contract) => isSupportVersionCompatible(contract)).forEach((contract) => {
    const current = latestBySlug.get(contract.slug);
    if (!current || compareContractVersions(contract.contract_version ?? '', current.contract_version ?? '') > 0) latestBySlug.set(contract.slug, contract);
  });
  return latestBySlug;
};

export const matchLocalCatalog = (facets: ResolvedFacets, contracts: BasicStoreEntityCatalogContract[]): CollectionGapRecommendedConnector[] => {
  const latestBySlug = latestCompatibleContractsBySlug(contracts);
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

/**
 * Time the XTM Hub requests of one computation may take together. The computation runs under the manager lock: once
 * the budget is spent, the remaining gaps use the local catalog, so a slow Hub holds the lock at most this long plus
 * the timeout of one request.
 */
export const HUB_QUERIES_BUDGET_MS = 60 * 1000;

export const hubQueriesBudget = (budgetMs = HUB_QUERIES_BUDGET_MS, now: () => number = Date.now) => {
  let spentMs = 0;
  return {
    track: async <T>(request: () => Promise<T>): Promise<T> => {
      const startedAt = now();
      try {
        return await request();
      } finally {
        spentMs += now() - startedAt;
      }
    },
    exhausted: () => spentMs >= budgetMs,
    spentMs: () => spentMs,
  };
};

/** XTM Hub catalog status of a gap: a truncated ranking is reported as partial, never as complete. */
export const hubCatalogStatusOf = (result: HubIntegrationCoverageResult): HubCatalogStatus => {
  return result.status === 'ok' && result.truncated ? 'partial' : result.status;
};

export const mergeRecommendedConnectors = (
  hubMatches: HubIntegrationCoverageMatch[],
  localMatches: CollectionGapRecommendedConnector[],
  contracts: BasicStoreEntityCatalogContract[],
  // Connectors of the platform: one deployed from any version of a recommended catalog entry counts as deployed
  connectors: ReadonlyArray<Parameters<typeof connectorMatchesCatalogEntry>[0]>,
  max: number,
): CollectionGapRecommendedConnector[] => {
  // A Hub recommendation deploys the same contract as a local one; without a compatible contract it is not deployable here
  const contractBySlug = latestCompatibleContractsBySlug(contracts);
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
    .map((match) => ({ ...match, deployed: connectors.some((connector) => connectorMatchesCatalogEntry(connector, match)) }))
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
type AddConnectorGap = Pick<BasicStoreEntityCollectionGap, 'internal_id' | 'pir_id' | 'criterion_key' | 'criterion_label' | 'gap_coverage_score'
  | 'recent_relationships' | 'matched_relationships' | 'distinct_sources'>;

/**
 * Recommendation to deploy one catalog connector for a collection gap. The fingerprint identifies the gap and the
 * connector, so the gap computation and a deployment requested from the gap share the same recommendation.
 */
export const buildAddConnectorProposal = (
  gap: AddConnectorGap,
  pirName: string,
  connector: CollectionGapRecommendedConnector,
  recentDays: number,
): RecommendationProposal => ({
  kind: RECOMMENDATION_ADD_CONNECTOR,
  source_id: null,
  fingerprint: recommendationFingerprint(RECOMMENDATION_ADD_CONNECTOR, gap.pir_id, gap.criterion_key, connector.slug),
  name: `Deploy ${connector.title} for ${pirName}`,
  rationale: `The criterion "${gap.criterion_label}" of the PIR ${pirName} has a coverage of ${gap.gap_coverage_score}/100 `
    + `(${gap.recent_relationships} relationships in the last ${recentDays} days from ${gap.distinct_sources} sources). `
    + `${connector.title} covers ${[...connector.matched_object_types, ...connector.matched_sectors, ...connector.matched_regions].join(', ') || 'this criterion'}.`,
  payload: {
    pir_id: gap.pir_id,
    collection_gap_id: gap.internal_id,
    slug: connector.slug,
    title: connector.title,
    catalog_id: connector.catalog_id,
    contract_image: connector.contract_image,
    origin: connector.origin,
    score: connector.score,
  },
  evidence: {
    coverage_score: gap.gap_coverage_score,
    recent_relationships: gap.recent_relationships,
    matched_relationships: gap.matched_relationships,
    distinct_sources: gap.distinct_sources,
  },
});

export const computeCollectionGaps = async (context: AuthContext, sources: BasicStoreEntitySource[], settings: SourceIntelligenceSettings) => {
  const pirs = await fullEntitiesList<BasicStoreEntityPir>(context, SYSTEM_USER, [ENTITY_TYPE_PIR]);
  const existingGaps = await fullEntitiesList<BasicStoreEntityCollectionGap>(context, SYSTEM_USER, [ENTITY_TYPE_COLLECTION_GAP]);
  const existingByKey = new Map(existingGaps.map((gap) => [`${gap.pir_id}|${gap.criterion_key}`, gap]));
  const contracts = await fullEntitiesList<BasicStoreEntityCatalogContract>(context, SYSTEM_USER, [ENTITY_TYPE_CATALOG_CONTRACT]);
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  const hubPlatform = await hubPlatformOf(context);
  // Once XTM Hub fails or uses up the time budget of the run, the remaining criteria use the local catalog
  let hubFailure: HubCatalogStatus | null = null;
  const hubBudget = hubQueriesBudget();
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
      const [windowCount, recentCount] = await Promise.all([
        countMatchingRelationships(context, finalFilters, settings.gaps.window_days),
        countMatchingRelationships(context, finalFilters, settings.gaps.recent_days),
      ]);
      const sample = await aggregateCoveringSources(context, finalFilters, settings.gaps.window_days, sources, windowCount);
      const coverage = computeGapCoverageScore({ recent: recentCount, window: windowCount, distinctSources: sample.distinct }, settings.gaps);
      const isGap = coverage < settings.thresholds.gap_coverage;
      let hubStatus: HubCatalogStatus = hubPlatform ? (hubFailure ?? 'ok') : 'not_registered';
      let recommended: CollectionGapRecommendedConnector[] = [];
      if (isGap) {
        let hubMatches: HubIntegrationCoverageMatch[] = [];
        if (hubPlatform && !hubFailure) {
          const hubResult = await hubBudget.track(() => xtmHubClient.integrationsByCoverage(hubPlatform, {
            objectTypes: resolved.objectTypes,
            sectors: resolved.sectors,
            regions: resolved.regions,
            integrationTypes: HUB_INTEGRATION_TYPES,
            first: settings.gaps.max_recommendations * 3,
          }));
          hubStatus = hubCatalogStatusOf(hubResult);
          hubMatches = hubResult.matches;
          if (hubResult.status === 'unreachable' || hubResult.status === 'error') {
            hubFailure = hubResult.status;
            logApp.warn('[OPENCTI-MODULE] Source intelligence stops querying XTM Hub for the rest of the run', { status: hubResult.status });
          } else if (hubBudget.exhausted()) {
            hubFailure = 'unreachable';
            logApp.warn('[OPENCTI-MODULE] Source intelligence stops querying XTM Hub for the rest of the run, its requests used up the time budget', {
              budget_ms: HUB_QUERIES_BUDGET_MS,
              spent_ms: hubBudget.spentMs(),
            });
          }
        }
        recommended = mergeRecommendedConnectors(hubMatches, matchLocalCatalog(resolved, contracts), contracts, connectors, settings.gaps.max_recommendations);
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
        proposals.push(buildAddConnectorProposal({ ...gapFields, internal_id: gapId }, pir.name, best, settings.gaps.recent_days));
      }
    }
  }
  // Criteria removed from their PIR, or deleted PIRs
  const removed = existingGaps.filter((gap) => !keptKeys.has(`${gap.pir_id}|${gap.criterion_key}`));
  for (let i = 0; i < removed.length; i += 1) {
    await deleteElementById(context, SOURCE_INTELLIGENCE_MANAGER_USER, removed[i].internal_id, ENTITY_TYPE_COLLECTION_GAP);
  }
  await upsertProposals(context, proposals, settings, { kinds: [RECOMMENDATION_ADD_CONNECTOR] });
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
    pirIds = await listAccessiblePirIds(context, user);
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

/**
 * Collection gaps read through a generic lookup by id (filter representatives), as findCollectionGaps serves them: in
 * Enterprise Edition, with the Sources capabilities, and for the PIRs the user can access.
 */
export const readableCollectionGaps = async (context: AuthContext, user: AuthUser, entities: BasicStoreEntity[]): Promise<Array<BasicStoreEntity | undefined>> => {
  if (!canReadSourceIntelligence(user) || !(await isEnterpriseEdition(context))) {
    return entities.map(() => undefined);
  }
  const accessiblePirIds = new Set(await listAccessiblePirIds(context, user));
  return (entities as unknown as BasicStoreEntityCollectionGap[])
    .map((gap) => (accessiblePirIds.has(gap.pir_id) ? gap as unknown as BasicStoreEntity : undefined));
};
// endregion

// region mutations
/**
 * One-click deployment, through XTM Composer, of a connector recommended for a collection gap. It runs as the
 * add_connector recommendation of the gap and connector (created when the gap computation did not propose this
 * connector), so the deployment is audited, listed in the recommendations inbox and reversible.
 */
export const deployCollectionGapConnector = async (
  context: AuthContext,
  user: AuthUser,
  gapId: string,
  slug: string,
  settings: SourceIntelligenceSettings,
  configuration: readonly ContractConfigInput[] = [],
) => {
  await checkEnterpriseEdition(context);
  const gap = await storeLoadById<BasicStoreEntityCollectionGap>(context, user, gapId, ENTITY_TYPE_COLLECTION_GAP);
  if (!gap) {
    throw FunctionalError('Collection gap not found', { id: gapId });
  }
  const pir = await getPirWithAccessCheck(context, user, gap.pir_id);
  const connector = (gap.recommended_connectors ?? []).find((recommended) => recommended.slug === slug);
  if (!connector) {
    throw FunctionalError('This connector is not recommended for the collection gap', { id: gapId, slug });
  }
  if (connector.deployed) {
    throw FunctionalError('This connector is already deployed', { id: gapId, slug });
  }
  if (!connector.manager_supported || !connector.contract_image) {
    throw FunctionalError('This connector cannot be deployed through XTM Composer, deploy it from the catalog page', { id: gapId, slug });
  }
  const proposal = buildAddConnectorProposal(gap, pir.name, connector, settings.gaps.recent_days);
  // The gap only knows the deployments of its last computation: repeated requests are checked against the live state
  let lock;
  try {
    lock = await lockResources([`collection-gap-deploy:${gap.internal_id}:${slug}`]);
    const connectors = await fullEntitiesList<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR]);
    const applied = await findRecommendationsByFingerprint(context, proposal.fingerprint, [RECOMMENDATION_STATUS_APPLIED, RECOMMENDATION_STATUS_REVERTING]);
    if (applied.length > 0 || connectors.some((deployed) => connectorMatchesCatalogEntry(deployed, connector))) {
      throw FunctionalError('This connector is already deployed', { id: gapId, slug });
    }
    const recommendation = await findOrCreateProposal(context, proposal);
    return await applySourceRecommendation(context, user, recommendation.internal_id, settings, { configuration });
  } catch (err: any) {
    if (err?.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [gap.internal_id] });
    }
    throw err;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};
// endregion
