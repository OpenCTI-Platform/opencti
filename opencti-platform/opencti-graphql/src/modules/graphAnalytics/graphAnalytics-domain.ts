import conf, { booleanConf, logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreObject, BasicStoreRelation, StoreEntity } from '../../types/store';
import { elAggregationSearch, elCount, elFindByIds, elHistogramCount, elList, isUserWithCompleteRelationshipsView } from '../../database/engine';
import { fullRelationsList, pageEntitiesConnection, pageRelationsConnection, storeLoadById } from '../../database/middleware-loader';
import { createRelation, deleteElementById } from '../../database/middleware';
import { fillTimeSeries, READ_ENTITIES_INDICES, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { isStixCoreRelationship, RELATION_RELATED_TO, RELATION_USES } from '../../schema/stixCoreRelationship';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_OBJECT } from '../../schema/stixRefRelationship';
import { getParentTypes, isInternalId } from '../../schema/schemaUtils';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import {
  type FilterGroup,
  FilterMode,
  FilterOperator,
  type GraphAnalyticsUpsertMetricsInput,
  type GraphClusterPromoteInput,
  GraphClusterPromotionTarget,
  type InputMaybe,
  OrderingMode,
} from '../../generated/graphql';
import { GRAPH_CLUSTER_ID_FILTER } from '../../utils/filtering/filtering-constants';
import { checkAndConvertFilters, type FiltersIdsFinder } from '../../utils/filtering/filtering-utils';
import { GRAPH_ANALYTICS_MANAGER_USER, isBypassUser, SYSTEM_USER } from '../../utils/access';
import {
  redisGraphAnalyticsAcquireRunLease,
  redisGraphAnalyticsGetState,
  redisGraphAnalyticsMarkPriority,
  redisGraphAnalyticsPendingCount,
  redisGraphAnalyticsPendingIds,
  redisGraphAnalyticsReleaseRunLease,
  redisGraphAnalyticsSetState,
} from '../../database/redis';
import { addGraphAnalyticsPivotCount, addGraphClusterPromotionCount, addGraphSimilarityQueryCount } from '../../manager/telemetryManager';
import { addGrouping } from '../grouping/grouping-domain';
import { addCampaign } from '../../domain/campaign';
import { RELATION_COVERED } from '../securityCoverage/securityCoverage-types';
import { addWorkspace, findById as findWorkspaceById, workspaceEditField } from '../workspace/workspace-domain';
import { isRelationConsistent } from '../../utils/modelConsistency';
import { nowTime } from '../../utils/format';
import {
  computeNextFullPassAt,
  lastFullPassEndedAt,
  getGraphAnalyticsComputeConfig,
  GRAPH_RUN_LEASE_MS,
  isFullPassInProgress,
  loadFeatureProfilesBatched,
  withRunLeaseHeartbeat,
  writeRunMetrics,
} from './graphAnalytics-compute';
import { isSameComparisonGroup, keepAccessibleEndpoints } from './graphAnalytics-features';
import { notifyClusterMemberships } from './graphAnalytics-notification';
import { computeSimilarityScore, type GraphSimilarityScore } from './graphAnalytics-scoring';
import {
  addClusterPromotion,
  computeVisibleDegreeMetrics,
  countSimilarityRows,
  finalizeClusteringRun,
  GRAPH_METRICS_ENTITY_INDICES,
  listRecentSimilarityEndpoints,
  listSimilarityRows,
  loadGraphClusters,
  upsertGraphClusters,
} from './graphAnalytics-store';
import {
  type BasicStoreEntityGraphCluster,
  ENTITY_TYPE_GRAPH_CLUSTER,
  GRAPH_FEATURE_FAMILIES,
  GRAPH_METRICS_ATTRIBUTE,
  type GraphClusterKind,
  type GraphClusterSource,
  type GraphFeatureFamily,
  type GraphMetrics,
  type GraphSimilarityDocument,
} from './graphAnalytics-types';
import {
  GRAPH_STATE_ANALYTICS_LAST_RUN_AT,
  GRAPH_STATE_ANALYTICS_LAST_RUN_ID,
  GRAPH_STATE_ANALYTICS_VERSION,
  GRAPH_STATE_FULL_PASS_COMPLETED_AT,
  GRAPH_STATE_FULL_PASS_STARTED_AT,
  GRAPH_STATE_LAST_INCREMENTAL_RUN,
  isAnalyticsProcessActive,
  parseStateDate,
} from './graphAnalytics-state';

const SIMILARITY_MAX_RESULTS: number = conf.get('graph_analytics:similarity_max_results') ?? 100;
const SIMILARITY_SCAN_WINDOW = 500;
const SIMILARITY_MAX_SCANNED_ROWS = 5000;
const MATRIX_MAX_ENTITIES: number = conf.get('graph_analytics:matrix_max_entities') ?? 25;
const MATRIX_MAX_CANDIDATES = 500;
const CLUSTER_AGGREGATION_PAGE_SIZE = 5000;
export const PROMOTION_MAX_MEMBERS = 2000;
// same limit as a promotion, the cluster page disables both actions above it
const INVESTIGATION_MAX_ELEMENTS = PROMOTION_MAX_MEMBERS;
const UPSERT_MAX_METRICS = 5000;
const UPSERT_MAX_CLUSTERS = 1000;
const EDGES_MAX_PAGE = 5000;
export const RECOMPUTE_MAX_IDS = 1000;

const clamp = (value: number | null | undefined, fallback: number, min: number, max: number) => {
  const number = value ?? fallback;
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(number)));
};

const accessibleMap = async <T extends BasicStoreBase>(context: AuthContext, user: AuthUser, ids: string[]): Promise<Record<string, T>> => {
  if (ids.length === 0) return {};
  return elFindByIds<T>(context, user, Array.from(new Set(ids)), { toMap: true, indices: READ_ENTITIES_INDICES }) as Promise<Record<string, T>>;
};

const buildConnection = <T>(nodes: T[], globalCount: number, hasNextPage = false) => ({
  edges: nodes.map((node, index) => ({ cursor: String(index), node })),
  pageInfo: {
    startCursor: nodes.length > 0 ? '0' : '',
    endCursor: nodes.length > 0 ? String(nodes.length - 1) : '',
    hasNextPage,
    hasPreviousPage: false,
    globalCount,
  },
});

// region similarity
export interface SimilarEntitiesArgs {
  id: string;
  first?: number | null;
  minScore?: number | null;
  entityTypes?: string[] | null;
  onlyWithSecurityCoverage?: boolean | null;
}

const findSecurityCoverages = async (context: AuthContext, user: AuthUser, coveredIds: string[]): Promise<Map<string, BasicStoreEntity>> => {
  const coverages = new Map<string, BasicStoreEntity>();
  if (coveredIds.length === 0) return coverages;
  const links = await fullRelationsList<BasicStoreRelation>(context, user, RELATION_COVERED, { toId: coveredIds, baseData: true });
  const coverageEntities = await accessibleMap<BasicStoreEntity>(context, user, links.map((l) => l.fromId));
  links.forEach((link) => {
    const coverage = coverageEntities[link.fromId];
    if (coverage && !coverages.has(link.toId)) coverages.set(link.toId, coverage);
  });
  return coverages;
};

const matchesEntityTypes = (entityType: string, entityTypes: string[] | null | undefined) => {
  if (!entityTypes || entityTypes.length === 0) return true;
  return entityTypes.includes(entityType) || getParentTypes(entityType).some((parent: string) => entityTypes.includes(parent));
};

interface QualifyingSimilarity {
  row: GraphSimilarityDocument;
  target: BasicStoreEntity;
  score: GraphSimilarityScore;
  families: Array<{ family: GraphFeatureFamily; entities: BasicStoreEntity[] }>;
}

/**
 * Top-N similar entities for the caller. The precomputed rows only select the candidates: every score is computed
 * again from profiles restricted to what the caller can access, so a hidden relationship never raises a score,
 * and a similarity without any visible evidence is dropped.
 */
export const findSimilarEntities = async (context: AuthContext, user: AuthUser, args: SimilarEntitiesArgs) => {
  const entity = await storeLoadById<BasicStoreEntity>(context, user, args.id, ABSTRACT_STIX_CORE_OBJECT);
  if (!entity) {
    throw FunctionalError('Entity not found or not accessible', { id: args.id });
  }
  const first = clamp(args.first, 10, 1, SIMILARITY_MAX_RESULTS);
  const minScore = args.minScore ?? 0;
  const config = getGraphAnalyticsComputeConfig();
  const [source] = await loadFeatureProfilesBatched(context, user, [{ id: entity.internal_id, entity_type: entity.entity_type }], config, true);
  // Every stored row (the top-N of the entity, bounded by SIMILARITY_MAX_SCANNED_ROWS) is scored again for the caller
  // before ranking: once the part of the graph the caller cannot see is left out, a row stored lower can score higher,
  // so the scan never stops at the first rows that qualify (types, access, visible evidence, security coverage).
  const qualifying: QualifyingSimilarity[] = [];
  const coverages = new Map<string, BasicStoreEntity>();
  let scanned = 0;
  let exhausted = !source;
  while (!exhausted && scanned < SIMILARITY_MAX_SCANNED_ROWS) {
    const rows = await listSimilarityRows(context, user, entity.internal_id, SIMILARITY_SCAN_WINDOW, 0, scanned);
    scanned += rows.length;
    exhausted = rows.length < SIMILARITY_SCAN_WINDOW;
    const typedRows = rows.filter((row) => matchesEntityTypes(row.similarity_target_type, args.entityTypes)
      && isSameComparisonGroup(entity.entity_type, row.similarity_target_type));
    const targets = await accessibleMap<BasicStoreEntity>(context, user, typedRows.map((r) => r.similarity_target_id));
    const candidates = typedRows.flatMap((row) => (targets[row.similarity_target_id] ? [{ row, target: targets[row.similarity_target_id] }] : []));
    const profiles = await loadFeatureProfilesBatched(context, user, candidates.map((c) => ({ id: c.target.internal_id, entity_type: c.target.entity_type })), config, true);
    const profilesById = new Map(profiles.map((p) => [p.id, p]));
    const scored = candidates.flatMap(({ row, target }) => {
      const profile = profilesById.get(target.internal_id);
      if (!source || !profile) return [];
      const score = computeSimilarityScore(source, profile);
      if (score.shared_count === 0 || score.score < minScore) return [];
      return [{ row, target, score }];
    });
    const evidenceIds = scored.flatMap(({ score }) => Object.values(score.shared).flat() as string[]);
    const evidence = await accessibleMap<BasicStoreEntity>(context, user, evidenceIds);
    const visibleRows = scored.flatMap(({ row, target, score }) => {
      const families = GRAPH_FEATURE_FAMILIES
        .map((family) => ({ family, entities: (score.shared[family] ?? []).map((id) => evidence[id]).filter(Boolean) }))
        .filter((f) => f.entities.length > 0);
      if (families.length === 0) return [];
      return [{ row, target, score, families }];
    });
    const windowCoverages = await findSecurityCoverages(context, user, visibleRows.map((v) => v.target.internal_id));
    windowCoverages.forEach((coverage, coveredId) => coverages.set(coveredId, coverage));
    qualifying.push(...visibleRows.filter((v) => !args.onlyWithSecurityCoverage || coverages.has(v.target.internal_id)));
  }
  qualifying.sort((x, y) => (y.score.score - x.score.score)
    || (y.score.shared_count - x.score.shared_count)
    || x.target.internal_id.localeCompare(y.target.internal_id));
  const nodes = qualifying
    .slice(0, first)
    .map(({ row, target, score, families }) => ({
      id: `${row.similarity_entity_id}_${row.similarity_target_id}`,
      score: score.score,
      jaccard: score.jaccard,
      structural: score.structural,
      computed_at: row.similarity_computed_at,
      shared_count: families.reduce((acc, f) => acc + f.entities.length, 0),
      entity: target,
      evidence: families,
      securityCoverage: coverages.get(target.internal_id) ?? null,
    }));
  addGraphSimilarityQueryCount();
  return buildConnection(nodes, qualifying.length, qualifying.length > nodes.length);
};

export interface GraphSimilarityMatrixArgs {
  ids?: string[] | null;
  types?: string[] | null;
  filters?: InputMaybe<FilterGroup>;
  first?: number | null;
}

/** Explicit ids, or the most connected entities matching a data selection (dashboard widgets). */
const loadMatrixEntities = async (context: AuthContext, user: AuthUser, args: GraphSimilarityMatrixArgs): Promise<BasicStoreEntity[]> => {
  if (args.ids && args.ids.length > 0) {
    const uniqueIds = Array.from(new Set(args.ids));
    if (uniqueIds.length > MATRIX_MAX_ENTITIES) {
      throw FunctionalError('Too many entities for a similarity matrix', { max: MATRIX_MAX_ENTITIES });
    }
    const loaded = await accessibleMap<BasicStoreEntity>(context, user, uniqueIds);
    return uniqueIds.map((id) => loaded[id]).filter(Boolean);
  }
  if (!args.filters && (!args.types || args.types.length === 0)) {
    throw FunctionalError('A similarity matrix needs entity ids, types or filters');
  }
  const limit = clamp(args.first, 10, 2, MATRIX_MAX_ENTITIES);
  const types = args.types && args.types.length > 0 ? args.types : [ABSTRACT_STIX_CORE_OBJECT];
  const filters = args.filters ?? undefined;
  if (await isUserWithCompleteRelationshipsView(context, user)) {
    return elList<BasicStoreEntity>(context, user, READ_ENTITIES_INDICES, {
      types,
      filters,
      orderBy: `${GRAPH_METRICS_ATTRIBUTE}.degree`,
      orderMode: OrderingMode.Desc,
      first: limit,
      maxSize: limit,
    });
  }
  // The stored degree counts relationships the caller may not read: the latest matches are ranked by visible degree
  const candidates = await elList<BasicStoreEntity>(context, user, READ_ENTITIES_INDICES, {
    types,
    filters,
    orderBy: 'created_at',
    orderMode: OrderingMode.Desc,
    first: MATRIX_MAX_CANDIDATES,
    maxSize: MATRIX_MAX_CANDIDATES,
  });
  const degrees = await computeVisibleDegreeMetrics(context, user, candidates.map((candidate) => candidate.internal_id));
  // an entity whose visible degree is not computed (too many relationships) ranks last: its rank must not reveal anything
  return candidates
    .map((entity, index) => ({ entity, index, degree: degrees.get(entity.internal_id)?.degree ?? -1 }))
    .sort((a, b) => (b.degree - a.degree) || (a.index - b.index))
    .slice(0, limit)
    .map(({ entity }) => entity);
};

/** Pairwise scores computed live from the caller's view of the knowledge (no precomputed data involved). */
export const graphSimilarityMatrix = async (context: AuthContext, user: AuthUser, args: GraphSimilarityMatrixArgs) => {
  const entities = await loadMatrixEntities(context, user, args);
  const profileEntities = entities.map((e) => ({ id: e.internal_id, entity_type: e.entity_type }));
  const profiles = await loadFeatureProfilesBatched(context, user, profileEntities, getGraphAnalyticsComputeConfig(), true);
  const byId = new Map(profiles.map((p) => [p.id, p]));
  const cells: Array<{ source_id: string; target_id: string; score: number; shared_count: number }> = [];
  for (let i = 0; i < entities.length; i += 1) {
    for (let j = 0; j < entities.length; j += 1) {
      if (i === j) continue;
      const a = byId.get(entities[i].internal_id);
      const b = byId.get(entities[j].internal_id);
      const comparable = a && b && isSameComparisonGroup(entities[i].entity_type, entities[j].entity_type);
      const score = comparable ? computeSimilarityScore(a, b) : { score: 0, shared_count: 0 };
      cells.push({ source_id: entities[i].internal_id, target_id: entities[j].internal_id, score: score.score, shared_count: score.shared_count });
    }
  }
  return { entities, cells };
};
// endregion

// region clusters
const filtersIdsFinder: FiltersIdsFinder = async (c, u, ids, opts) => {
  return elFindByIds<BasicStoreObject>(c, u, ids, { ...opts, toMap: true }) as Promise<Record<string, BasicStoreObject>>;
};

const clusterMembersFilter = (clusterId: string, filters?: InputMaybe<FilterGroup>): FilterGroup => ({
  mode: FilterMode.And,
  filters: [{ key: [GRAPH_CLUSTER_ID_FILTER], values: [clusterId] }],
  filterGroups: filters ? [filters] : [],
});

// The aggregations filter on raw metric fields (no filter key), so the member filters are checked and converted here
const clusterMembersAggregationFilters = async (
  context: AuthContext,
  user: AuthUser,
  kinds?: GraphClusterKind[] | null,
  memberFilters?: InputMaybe<FilterGroup>,
): Promise<FilterGroup> => {
  const convertedMemberFilters = memberFilters
    ? await checkAndConvertFilters(context, user, memberFilters, user.id, filtersIdsFinder)
    : undefined;
  return {
    mode: FilterMode.And,
    filters: [
      { key: [`${GRAPH_METRICS_ATTRIBUTE}.cluster_id`], values: [], operator: FilterOperator.NotNil },
      ...(kinds && kinds.length > 0 ? [{ key: [`${GRAPH_METRICS_ATTRIBUTE}.cluster_kind`], values: kinds }] : []),
    ],
    filterGroups: convertedMemberFilters ? [convertedMemberFilters] : [],
  };
};

/**
 * The `max` clusters with the most members visible to the caller (and matching optional member filters), in one
 * aggregation. While the clusters fit in `max`, every shard returns all of its clusters and the counts are exact;
 * `limited` tells that larger platforms only got their largest clusters.
 */
export const largestVisibleClusters = async (
  context: AuthContext,
  user: AuthUser,
  max: number,
  kinds?: GraphClusterKind[] | null,
  memberFilters?: InputMaybe<FilterGroup>,
): Promise<{ counts: Map<string, number>; limited: boolean }> => {
  const filters = await clusterMembersAggregationFilters(context, user, kinds, memberFilters);
  const aggregations = await elAggregationSearch(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters, noFiltersChecking: true }, {
    largest: {
      terms: {
        field: `${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword`,
        size: max,
        shard_size: max,
        order: [{ _count: 'desc' }, { _key: 'asc' }],
      },
    },
  });
  const buckets: any[] = aggregations.largest?.buckets ?? [];
  return {
    counts: new Map(buckets.map((bucket) => [String(bucket.key), bucket.doc_count])),
    limited: (aggregations.largest?.sum_other_doc_count ?? 0) > 0,
  };
};

/** Number of cluster members visible to the caller (and matching optional member filters), per cluster. */
const visibleMembersPerCluster = async (
  context: AuthContext,
  user: AuthUser,
  kinds?: GraphClusterKind[] | null,
  memberFilters?: InputMaybe<FilterGroup>,
): Promise<Map<string, number>> => {
  const filters = await clusterMembersAggregationFilters(context, user, kinds, memberFilters);
  const counts = new Map<string, number>();
  let after: Record<string, unknown> | undefined;
  do {
    const aggregations = await elAggregationSearch(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters, noFiltersChecking: true }, {
      clusters: {
        composite: {
          size: CLUSTER_AGGREGATION_PAGE_SIZE,
          sources: [{ cluster_id: { terms: { field: `${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword` } } }],
          ...(after ? { after } : {}),
        },
      },
    });
    const buckets: any[] = aggregations.clusters?.buckets ?? [];
    buckets.forEach((bucket) => counts.set(String(bucket.key.cluster_id), bucket.doc_count));
    after = buckets.length === CLUSTER_AGGREGATION_PAGE_SIZE ? aggregations.clusters?.after_key : undefined;
  } while (after);
  return counts;
};

const countVisibleMembers = async (context: AuthContext, user: AuthUser, clusterId: string) => {
  return elCount(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters: clusterMembersFilter(clusterId) });
};

/** Number of members visible to the caller for each given cluster, keyed by lower-cased cluster id. */
const countVisibleMembersOfClusters = async (context: AuthContext, user: AuthUser, clusterIds: string[]): Promise<Map<string, number>> => {
  const counts = new Map<string, number>();
  if (clusterIds.length === 0) return counts;
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: [{ key: [`${GRAPH_METRICS_ATTRIBUTE}.cluster_id`], values: clusterIds }],
    filterGroups: [],
  };
  const aggregations = await elAggregationSearch(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters, noFiltersChecking: true }, {
    clusters: { terms: { field: `${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword`, size: clusterIds.length } },
  });
  const buckets: any[] = aggregations.clusters?.buckets ?? [];
  buckets.forEach((bucket) => counts.set(String(bucket.key).toLowerCase(), bucket.doc_count));
  return counts;
};

/**
 * x_opencti_graph_metrics as the caller may read them. The stored metrics count every relationship of the platform and
 * are returned as is to callers reading all of them. For the others, degree and cluster size are counted again from
 * what they can access, and the betweenness, which cannot be derived from a partial view of the graph, is withheld.
 */
export const batchGraphMetrics = async (context: AuthContext, user: AuthUser, elements: BasicStoreBase[]): Promise<Array<GraphMetrics | null>> => {
  const stored = elements.map((element) => (element as unknown as Record<string, GraphMetrics | null | undefined>)[GRAPH_METRICS_ATTRIBUTE] ?? null);
  if (stored.every((metrics) => !metrics) || await isUserWithCompleteRelationshipsView(context, user)) {
    return stored;
  }
  const measuredIds = elements.filter((_, index) => stored[index]).map((element) => element.internal_id);
  const clusterIds = Array.from(new Set(stored.map((metrics) => metrics?.cluster_id).filter((id): id is string => !!id)));
  const [degrees, clusterSizes] = await Promise.all([
    computeVisibleDegreeMetrics(context, user, measuredIds),
    countVisibleMembersOfClusters(context, user, clusterIds),
  ]);
  return elements.map((element, index) => {
    const metrics = stored[index];
    if (!metrics) return null;
    // null: more relationships than can be counted for this reader, never a partial count
    const visibleDegree = degrees.get(element.internal_id) ?? null;
    return {
      ...metrics,
      degree: visibleDegree?.degree ?? null,
      degree_by_type: visibleDegree?.degree_by_type ?? null,
      betweenness_approx: null,
      cluster_size: metrics.cluster_id ? (clusterSizes.get(metrics.cluster_id.toLowerCase()) ?? 0) : null,
    };
  });
};

export const loadGraphMetrics = async (context: AuthContext, user: AuthUser, element: BasicStoreBase): Promise<GraphMetrics | null> => {
  const loader = context.batch?.graphMetricsBatchLoader;
  if (loader) return loader.load(element);
  const [metrics] = await batchGraphMetrics(context, user, [element]);
  return metrics;
};

export interface GraphClustersArgs {
  first?: number | null;
  after?: string | null;
  search?: string | null;
  kinds?: GraphClusterKind[] | null;
  sources?: GraphClusterSource[] | null;
  orderBy?: string | null;
  orderMode?: OrderingMode | null;
  filters?: InputMaybe<FilterGroup>;
  // filters on the member entities: only clusters with matching visible members are listed
  memberFilters?: InputMaybe<FilterGroup>;
}

const CLUSTER_IDS_CHUNK = 10000;
// one chunk of identifiers: the clusters of a page are matched by a single search
export const GRAPH_CLUSTERS_LIST_MAX = CLUSTER_IDS_CHUNK;
const compareText = (a?: string | null, b?: string | null) => (a ?? '').localeCompare(b ?? '');
// Relevance of a cluster found by a search ordered by _score: the first sort value of its hit.
const searchScore = (cluster: BasicStoreEntityGraphCluster) => {
  const score = cluster.sort?.[0];
  return typeof score === 'number' ? score : 0;
};
// No name sorter: readers see a cluster under its first accessible representative, not under its stored name
const CLUSTER_SORTERS: Record<string, (a: BasicStoreEntityGraphCluster, b: BasicStoreEntityGraphCluster) => number> = {
  cluster_kind: (a, b) => compareText(a.cluster_kind, b.cluster_kind),
  members_count: (a, b) => a.members_count - b.members_count,
  last_computed_at: (a, b) => compareText(a.last_computed_at ? String(a.last_computed_at) : null, b.last_computed_at ? String(b.last_computed_at) : null),
  _score: (a, b) => searchScore(a) - searchScore(b),
};

export interface RankedGraphCluster {
  id: string;
  members_count: number;
  cluster: BasicStoreEntityGraphCluster;
}

/**
 * Orders the clusters matched by every chunk of identifiers together: the engine only ranks each chunk within itself,
 * so a page cut from the concatenated chunks would otherwise favour the earlier chunks. Ties are broken by id.
 */
export const rankGraphClusters = (entries: RankedGraphCluster[], orderBy: string, orderMode?: OrderingMode | null) => {
  const sorter = CLUSTER_SORTERS[orderBy];
  if (!sorter) return entries;
  const direction = orderMode === OrderingMode.Asc ? 1 : -1;
  return [...entries].sort((a, b) => (direction * sorter({ ...a.cluster, members_count: a.members_count }, { ...b.cluster, members_count: b.members_count }))
    || a.id.localeCompare(b.id));
};

// Entities matching a cluster search that the caller can access, the most relevant first
const CLUSTER_REPRESENTATIVE_SEARCH_MAX = 1000;
const searchClusterRepresentativeIds = async (context: AuthContext, user: AuthUser, search: string) => {
  const entities = await elList<BasicStoreEntity>(context, user, READ_ENTITIES_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    search,
    baseData: true,
    first: CLUSTER_REPRESENTATIVE_SEARCH_MAX,
    maxSize: CLUSTER_REPRESENTATIVE_SEARCH_MAX,
  });
  return entities.map((entity) => entity.internal_id);
};

/**
 * Clusters having at least one member visible to the caller; members_count is the visible count. Only the
 * GRAPH_CLUSTERS_LIST_MAX largest are listed, so a page costs one aggregation and one search whatever the platform size,
 * plus one search of the representatives when the list is searched.
 */
export const findGraphClusters = async (context: AuthContext, user: AuthUser, args: GraphClustersArgs) => {
  const { counts: visible, limited } = await largestVisibleClusters(context, user, GRAPH_CLUSTERS_LIST_MAX, args.kinds, args.memberFilters);
  if (limited) {
    logApp.info('[OPENCTI-MODULE] Graph analytics cluster list limited to the largest clusters', { max: GRAPH_CLUSTERS_LIST_MAX });
  }
  if (visible.size === 0) return buildConnection([], 0);
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: [
      ...(args.kinds && args.kinds.length > 0 ? [{ key: ['cluster_kind'], values: args.kinds }] : []),
      ...(args.sources && args.sources.length > 0 ? [{ key: ['cluster_source'], values: args.sources }] : []),
    ],
    filterGroups: args.filters ? [args.filters] : [],
  };
  const visibleCount = (cluster: BasicStoreEntityGraphCluster) => visible.get(cluster.internal_id.toLowerCase()) ?? visible.get(cluster.internal_id) ?? 0;
  const first = clamp(args.first, 25, 1, 500);
  const orderBy = args.orderBy ?? 'members_count';
  // Readers see a cluster under its representatives they can access, its stored name only in a tooltip: a search
  // matches both, the representatives among the entities of the caller that match it.
  const representativeIds = new Set(args.search ? await searchClusterRepresentativeIds(context, user, args.search) : []);
  // Clusters are ranked here and not by the engine: members_count must be the visible count, and the visible
  // clusters are matched by chunks of identifiers below the terms query limit.
  const matchingById = new Map<string, BasicStoreEntityGraphCluster>();
  const visibleIds = Array.from(visible.keys());
  for (let index = 0; index < visibleIds.length; index += CLUSTER_IDS_CHUNK) {
    const chunkIds = visibleIds.slice(index, index + CLUSTER_IDS_CHUNK);
    const listChunk = (search?: string | null) => elList<BasicStoreEntityGraphCluster>(context, user, [READ_INDEX_INTERNAL_OBJECTS], {
      types: [ENTITY_TYPE_GRAPH_CLUSTER],
      ids: chunkIds,
      search,
      filters,
      baseData: true,
      baseFields: ['name', 'cluster_kind', 'last_computed_at', 'representative_ids'],
      ...(orderBy === '_score' ? { orderBy: '_score', orderMode: args.orderMode ?? OrderingMode.Desc } : {}),
    });
    (await listChunk(args.search)).forEach((cluster) => matchingById.set(cluster.internal_id, cluster));
    if (representativeIds.size > 0) {
      (await listChunk()).forEach((cluster) => {
        if (!matchingById.has(cluster.internal_id) && (cluster.representative_ids ?? []).some((id) => representativeIds.has(id))) {
          matchingById.set(cluster.internal_id, cluster);
        }
      });
    }
  }
  const matching = Array.from(matchingById.values());
  const ranked = rankGraphClusters(
    matching.map((cluster) => ({ id: cluster.internal_id, members_count: visibleCount(cluster), cluster })),
    orderBy,
    args.orderMode,
  );
  const offset = args.after ? Math.max(0, (Number.parseInt(args.after, 10) || 0) + 1) : 0;
  const page = ranked.slice(offset, offset + first);
  const loaded = await loadGraphClusters(context, user, page.map((entry) => entry.id));
  const loadedById = new Map(loaded.map((cluster) => [cluster.internal_id, cluster]));
  const nodes = page.flatMap((entry) => {
    const cluster = loadedById.get(entry.id);
    return cluster ? [{ ...cluster, members_count: entry.members_count }] : [];
  });
  return {
    edges: nodes.map((node, index) => ({ cursor: String(offset + index), node })),
    pageInfo: {
      startCursor: nodes.length > 0 ? String(offset) : '',
      endCursor: nodes.length > 0 ? String(offset + nodes.length - 1) : '',
      hasNextPage: offset + page.length < ranked.length,
      hasPreviousPage: offset > 0,
      globalCount: ranked.length,
    },
  };
};

export const findGraphClusterById = async (context: AuthContext, user: AuthUser, id: string): Promise<BasicStoreEntityGraphCluster | null> => {
  const [cluster] = await loadGraphClusters(context, user, [id]);
  if (!cluster) return null;
  const visibleCount = await countVisibleMembers(context, user, cluster.internal_id);
  if (visibleCount === 0) return null;
  return { ...cluster, members_count: visibleCount };
};

export const graphClusterRepresentatives = async (context: AuthContext, user: AuthUser, cluster: BasicStoreEntityGraphCluster) => {
  const ids = cluster.representative_ids ?? [];
  const entities = await accessibleMap<BasicStoreEntity>(context, user, ids);
  return ids.map((id) => entities[id]).filter(Boolean);
};

export const graphClusterFeatures = async (context: AuthContext, user: AuthUser, cluster: BasicStoreEntityGraphCluster) => {
  const features = cluster.cluster_features ?? [];
  const entities = await accessibleMap<BasicStoreEntity>(context, user, features.flatMap((f) => f.ids ?? []));
  return features
    .map((feature) => {
      const visibleEntities = (feature.ids ?? []).map((id) => entities[id]).filter(Boolean);
      return { family: feature.family, count: visibleEntities.length, entities: visibleEntities };
    })
    .filter((feature) => feature.count > 0);
};

export const graphClusterPromotedTo = async (context: AuthContext, user: AuthUser, cluster: BasicStoreEntityGraphCluster) => {
  const ids = cluster.promoted_to_ids ?? [];
  const entities = await accessibleMap<BasicStoreEntity>(context, user, ids);
  return ids.map((id) => entities[id]).filter(Boolean);
};

export interface GraphClusterMembersArgs {
  first?: number | null;
  after?: string | null;
  search?: string | null;
  types?: Array<string | null> | null;
  orderBy?: any;
  orderMode?: OrderingMode | null;
  filters?: InputMaybe<FilterGroup>;
}

export const graphClusterMembers = async (context: AuthContext, user: AuthUser, cluster: BasicStoreEntityGraphCluster, args: GraphClusterMembersArgs) => {
  const types = (args.types ?? []).filter((t): t is string => !!t);
  return pageEntitiesConnection(context, user, types.length > 0 ? types : [ABSTRACT_STIX_CORE_OBJECT], {
    first: clamp(args.first, 25, 1, 500),
    after: args.after,
    search: args.search,
    orderBy: args.orderBy,
    orderMode: args.orderMode ?? undefined,
    filters: clusterMembersFilter(cluster.internal_id, args.filters),
  });
};

export interface TimeSeriesArgs {
  startDate?: string | Date | null;
  endDate?: string | Date | null;
  interval: string;
}

/** Cumulative number of visible members over time, by the date each member joined the cluster (cluster_joined_at). */
export const graphClusterTimeline = async (
  context: AuthContext,
  user: AuthUser,
  clusterId: string,
  args: TimeSeriesArgs,
  memberFilters?: InputMaybe<FilterGroup>,
) => {
  const endDate = args.endDate ? new Date(args.endDate) : new Date();
  const startDate = args.startDate ? new Date(args.startDate) : new Date(endDate.getTime() - 365 * 24 * 3600 * 1000);
  const filters = clusterMembersFilter(clusterId, memberFilters);
  // members are counted from the date they joined the cluster, not from their own creation date
  const joinedAt = `${GRAPH_METRICS_ATTRIBUTE}.cluster_joined_at`;
  const baseline = await elCount(context, user, GRAPH_METRICS_ENTITY_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    filters,
    endDate: startDate.toISOString(),
    dateAttribute: joinedAt,
  });
  const histogram = await elHistogramCount(context, user, GRAPH_METRICS_ENTITY_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    filters,
    field: joinedAt,
    interval: args.interval,
    startDate: startDate.toISOString(),
    endDate: endDate.toISOString(),
  });
  const series = fillTimeSeries(startDate, endDate, args.interval, histogram);
  let cumulated = baseline;
  return series.map((point) => {
    cumulated += point.value;
    return { date: point.date, value: cumulated };
  });
};

export interface GraphClustersSizeArgs extends TimeSeriesArgs {
  kinds?: GraphClusterKind[] | null;
  clusterIds?: string[] | null;
  limit?: number | null;
  // filters on the member entities: the largest clusters by matching visible members, each series counting them only
  filters?: InputMaybe<FilterGroup>;
}

export const graphClustersSizeTimeSeries = async (context: AuthContext, user: AuthUser, args: GraphClustersSizeArgs) => {
  const limit = clamp(args.limit, 5, 1, 20);
  let clusters: BasicStoreEntityGraphCluster[];
  if (args.clusterIds && args.clusterIds.length > 0) {
    const loaded = await Promise.all(args.clusterIds.slice(0, limit).map((id) => findGraphClusterById(context, user, id)));
    clusters = loaded.filter((c): c is BasicStoreEntityGraphCluster => !!c);
  } else if (args.filters) {
    const visible = await visibleMembersPerCluster(context, user, args.kinds, args.filters);
    const largest = Array.from(visible.entries()).sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0])).slice(0, limit);
    const loaded = await loadGraphClusters(context, user, largest.map(([clusterId]) => clusterId));
    const byId = new Map(loaded.map((cluster) => [cluster.internal_id.toLowerCase(), cluster]));
    clusters = largest.flatMap(([clusterId, count]) => {
      const cluster = byId.get(clusterId.toLowerCase());
      return cluster ? [{ ...cluster, members_count: count }] : [];
    });
  } else {
    const connection = await findGraphClusters(context, user, { kinds: args.kinds, first: limit, orderBy: 'members_count', orderMode: OrderingMode.Desc });
    clusters = connection.edges.map((edge) => edge.node);
  }
  return Promise.all(clusters.map(async (cluster) => ({
    cluster,
    data: await graphClusterTimeline(context, user, cluster.internal_id, args, args.filters),
  })));
};

// loads up to max + 1 members: a clustering run can publish members after the count was read, and the caller
// must see that the cluster outgrew its limit instead of receiving the first max members
const loadVisibleMemberIds = async (context: AuthContext, user: AuthUser, clusterId: string, max: number) => {
  const members = await elList<BasicStoreEntity>(context, user, GRAPH_METRICS_ENTITY_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    filters: clusterMembersFilter(clusterId),
    baseData: true,
    first: Math.min(max + 1, 1000),
    maxSize: max + 1,
  });
  return members;
};

const loadClusterOrFail = async (context: AuthContext, user: AuthUser, id: string) => {
  const cluster = await findGraphClusterById(context, user, id);
  if (!cluster) throw FunctionalError('Graph cluster not found or without any accessible member', { id });
  return cluster;
};

/** Explicit analyst action: create a Grouping or a Campaign from the visible members of a cluster. */
export const promoteGraphCluster = async (context: AuthContext, user: AuthUser, id: string, input: GraphClusterPromoteInput) => {
  const cluster = await loadClusterOrFail(context, user, id);
  // the created knowledge must hold every accessible member, never a silent subset
  if (cluster.members_count > PROMOTION_MAX_MEMBERS) {
    throw FunctionalError('Graph cluster has too many accessible members to be promoted', { id, members: cluster.members_count, max: PROMOTION_MAX_MEMBERS });
  }
  const members = await loadVisibleMemberIds(context, user, cluster.internal_id, PROMOTION_MAX_MEMBERS);
  if (members.length > PROMOTION_MAX_MEMBERS) {
    throw FunctionalError('Graph cluster has too many accessible members to be promoted', { id, members: members.length, max: PROMOTION_MAX_MEMBERS });
  }
  const featureIds = input.include_features
    ? (await graphClusterFeatures(context, user, cluster)).flatMap((f) => f.entities.map((e) => e.internal_id))
    : [];
  const baseInput = {
    name: input.name,
    description: input.description ?? '',
    createdBy: input.createdBy ?? undefined,
    objectMarking: input.objectMarking ?? [],
  };
  // A Campaign of the same name is upserted, not created: it comes back with its own creation date. A Grouping is always
  // new: its identifier holds its creation date, which the promotion leaves to the platform. A failed promotion deletes
  // only what it created - its new Campaign or Grouping with their relationships, or the relationships it added to an
  // existing Campaign - and never knowledge that existed before it.
  const startedAt = Date.now();
  const isCreatedByPromotion = (element: { created_at?: Date | string }) => !element.created_at || new Date(element.created_at).getTime() >= startedAt;
  const addedRelationIds: string[] = [];
  const rollback = async (element: BasicStoreEntity) => {
    const removals = isCreatedByPromotion(element)
      ? [{ id: element.internal_id, type: element.entity_type }]
      : addedRelationIds.map((relationId) => ({ id: relationId, type: ABSTRACT_STIX_CORE_RELATIONSHIP }));
    for (let i = 0; i < removals.length; i += 1) {
      await deleteElementById(context, SYSTEM_USER, removals[i].id, removals[i].type).catch((rollbackError) => {
        logApp.error('[OPENCTI-MODULE] Graph analytics promotion rollback failed', { cause: rollbackError, elementId: removals[i].id });
      });
    }
  };
  let created: BasicStoreEntity;
  if (input.target === GraphClusterPromotionTarget.Grouping) {
    const objects = Array.from(new Set([...members.map((m) => m.internal_id), ...featureIds]));
    created = await addGrouping(context, user, { ...baseInput, context: 'suspicious-activity', objects }) as unknown as BasicStoreEntity;
  } else {
    const featureEntities = await accessibleMap<BasicStoreEntity>(context, user, featureIds);
    const targets = [...members, ...Object.values(featureEntities)];
    const campaign = await addCampaign(context, user, baseInput) as BasicStoreEntity;
    try {
      for (let i = 0; i < targets.length; i += 1) {
        const target = targets[i];
        const relationshipType = await isRelationConsistent(context, user, RELATION_USES, campaign, target) ? RELATION_USES : RELATION_RELATED_TO;
        if (relationshipType === RELATION_USES || await isRelationConsistent(context, user, relationshipType, campaign, target)) {
          const relation = await createRelation(context, user, {
            fromId: campaign.internal_id,
            toId: target.internal_id,
            relationship_type: relationshipType,
            objectMarking: input.objectMarking ?? [],
            createdBy: input.createdBy ?? undefined,
          }) as BasicStoreRelation;
          if (isCreatedByPromotion(relation)) addedRelationIds.push(relation.internal_id);
        }
      }
    } catch (error) {
      // a failed promotion must not leave a partially related Campaign
      await rollback(campaign);
      throw error;
    }
    created = campaign;
  }
  try {
    await addClusterPromotion(context, cluster, created.internal_id);
  } catch (error) {
    // a promotion is only kept when the cluster lists it
    await rollback(created);
    throw error;
  }
  addGraphClusterPromotionCount();
  return created;
};

export const addGraphClusterToInvestigation = async (context: AuthContext, user: AuthUser, id: string, investigationId?: string | null) => {
  const cluster = await loadClusterOrFail(context, user, id);
  // the investigation must hold every accessible member and shared feature, never a silent subset
  if (cluster.members_count > INVESTIGATION_MAX_ELEMENTS) {
    throw FunctionalError('Graph cluster has too many accessible elements to be added to an investigation', { id, elements: cluster.members_count, max: INVESTIGATION_MAX_ELEMENTS });
  }
  const members = await loadVisibleMemberIds(context, user, cluster.internal_id, INVESTIGATION_MAX_ELEMENTS);
  if (members.length > INVESTIGATION_MAX_ELEMENTS) {
    throw FunctionalError('Graph cluster has too many accessible elements to be added to an investigation', { id, elements: members.length, max: INVESTIGATION_MAX_ELEMENTS });
  }
  const features = await graphClusterFeatures(context, user, cluster);
  const ids = Array.from(new Set([...members.map((m) => m.internal_id), ...features.flatMap((f) => f.entities.map((e) => e.internal_id))]));
  if (ids.length > INVESTIGATION_MAX_ELEMENTS) {
    throw FunctionalError('Graph cluster has too many accessible elements to be added to an investigation', { id, elements: ids.length, max: INVESTIGATION_MAX_ELEMENTS });
  }
  let workspace;
  if (investigationId) {
    const existing = await findWorkspaceById(context, user, investigationId);
    if (!existing || existing.type !== 'investigation') {
      throw FunctionalError('Investigation not found', { id: investigationId });
    }
    workspace = await workspaceEditField(context, user, investigationId, [{ key: 'investigated_entities_ids', value: ids, operation: 'add' as any }]);
  } else {
    workspace = await addWorkspace(context, user, { type: 'investigation', name: `${cluster.name} (${nowTime()})`, investigated_entities_ids: ids });
  }
  addGraphAnalyticsPivotCount();
  return workspace;
};
// endregion

// region opencti-analytics process contract
const EDGE_ALLOWED_TYPES = (type: string) => type === ABSTRACT_STIX_CORE_RELATIONSHIP || type === STIX_SIGHTING_RELATIONSHIP
  || type === RELATION_OBJECT || isStixCoreRelationship(type);

export interface GraphAnalyticsEdgesArgs {
  relationshipTypes: string[];
  includeInferred?: boolean | null;
  first?: number | null;
  after?: string | null;
}

/**
 * Compact edge export (ids and types only) for the opencti-analytics process, computed as the caller.
 * An edge is only exported when the caller can read both endpoints; the page cursors are those of the
 * underlying relationships, so a page can hold fewer edges than requested, or none, while the cursor moves on.
 */
export const listGraphAnalyticsEdges = async (context: AuthContext, user: AuthUser, args: GraphAnalyticsEdgesArgs) => {
  if (args.relationshipTypes.length === 0) {
    throw FunctionalError('At least one relationship type is required');
  }
  args.relationshipTypes.forEach((type) => {
    if (!EDGE_ALLOWED_TYPES(type)) throw FunctionalError('Relationship type not supported by graph analytics', { type });
  });
  const connection = await pageRelationsConnection<BasicStoreRelation>(context, user, args.relationshipTypes, {
    first: clamp(args.first, 1000, 1, EDGES_MAX_PAGE),
    after: args.after,
    baseData: true,
    withInferences: !!args.includeInferred,
  });
  const relations = connection.edges.map((edge) => edge.node);
  const visible = new Set(await keepAccessibleEndpoints(context, user, relations, !isBypassUser(user)));
  return {
    pageInfo: connection.pageInfo,
    edges: connection.edges.filter((edge) => visible.has(edge.node)).map((edge) => ({
      cursor: edge.cursor,
      node: {
        id: edge.node.internal_id,
        relationship_type: edge.node.relationship_type,
        from_id: edge.node.fromId,
        from_type: edge.node.fromType,
        to_id: edge.node.toId,
        to_type: edge.node.toType,
      },
    })),
  };
};

/**
 * Write-back of the opencti-analytics process. Each metric entry carries all the run-owned metrics of an entity
 * (cluster assignment and centrality): an omitted cluster detaches the entity. Only entities the service account
 * can access are updated. `complete` finalizes the run: clusters and assignments of older runs are removed,
 * platform-wide, so it is only accepted from an account that bypasses data restrictions and analyzed the whole graph.
 */
export const upsertGraphAnalyticsMetrics = async (context: AuthContext, user: AuthUser, input: GraphAnalyticsUpsertMetricsInput) => {
  if (input.complete && !isBypassUser(user)) {
    throw ForbiddenAccess('Completing a graph analytics run requires an account that bypasses data restrictions');
  }
  if (input.metrics.length > UPSERT_MAX_METRICS) {
    throw FunctionalError('Too many metrics in one call', { max: UPSERT_MAX_METRICS });
  }
  const clusters = input.clusters ?? [];
  if (clusters.length > UPSERT_MAX_CLUSTERS) {
    throw FunctionalError('Too many clusters in one call', { max: UPSERT_MAX_CLUSTERS });
  }
  const invalidCluster = [...clusters.map((c) => c.cluster_id), ...input.metrics.map((m) => m.cluster_id).filter((c): c is string => !!c)]
    .find((clusterId) => !isInternalId(clusterId));
  if (invalidCluster) {
    throw FunctionalError('Cluster identifiers must be UUIDs', { cluster_id: invalidCluster });
  }
  // the staged metrics and clusters of an entity have one slot: a single run writes at a time
  if (!(await redisGraphAnalyticsAcquireRunLease(input.run_id, GRAPH_RUN_LEASE_MS))) {
    throw FunctionalError('Another graph analytics run is in progress', { run_id: input.run_id });
  }
  const state: Record<string, string> = { [GRAPH_STATE_ANALYTICS_LAST_RUN_ID]: input.run_id };
  if (input.process_version) state[GRAPH_STATE_ANALYTICS_VERSION] = input.process_version;
  const { updated, skipped, upserted, finalized } = await withRunLeaseHeartbeat(input.run_id, async (assertRunLease) => {
    const written = await writeRunMetrics(context, user, input.run_id, input.metrics.map((metric) => ({
      entity_id: metric.entity_id,
      cluster_id: metric.cluster_id ?? null,
      cluster_kind: (metric.cluster_kind as GraphClusterKind | null | undefined) ?? null,
      cluster_size: metric.cluster_size ?? null,
      betweenness_approx: metric.betweenness_approx ?? null,
    })));
    await assertRunLease();
    const upsertedClusters = await upsertGraphClusters(context, user, clusters.map((cluster) => ({
      cluster_id: cluster.cluster_id,
      cluster_kind: cluster.cluster_kind as GraphClusterKind,
      members_count: cluster.members_count,
      representative_ids: cluster.representative_ids.slice(0, 20),
      features: (cluster.features ?? []).map((f) => ({ family: f.family as GraphFeatureFamily, ids: f.ids.slice(0, 50) })),
    })), 'analytics', input.run_id);
    const finalizedRun = input.complete ? await finalizeClusteringRun(context, GRAPH_ANALYTICS_MANAGER_USER, input.run_id, assertRunLease) : null;
    // recorded while the lease is held: a platform clustering run taking the lease next sees the process active
    if (finalizedRun) state[GRAPH_STATE_ANALYTICS_LAST_RUN_AT] = new Date().toISOString();
    await redisGraphAnalyticsSetState(state);
    return { ...written, upserted: upsertedClusters, finalized: finalizedRun };
  });
  const removed = finalized?.removed ?? [];
  if (finalized) {
    await redisGraphAnalyticsReleaseRunLease(input.run_id);
    await notifyClusterMemberships(context, finalized.publishedAt);
  }
  return {
    run_id: input.run_id,
    updated_entities: updated,
    skipped_entities: skipped,
    upserted_clusters: upserted,
    removed_clusters: removed.length,
  };
};

const PENDING_ENTITIES_MAX = 100;
// queued entities the caller cannot access are skipped: the scan reads this many queued ids at most
const PENDING_SCAN_MAX = 2000;
const PENDING_SCAN_CHUNK = 200;
// the waiting count of a caller without the bypass covers this many queued ids at most
const PENDING_COUNT_SCAN_MAX = 10000;

/** Entities waiting for a recompute: the whole queue for an account that bypasses data restrictions, the ones the caller can access otherwise. */
const countGraphAnalyticsPendingEntities = async (context: AuthContext, user: AuthUser): Promise<number> => {
  if (isBypassUser(user)) return redisGraphAnalyticsPendingCount();
  const ids = await redisGraphAnalyticsPendingIds(PENDING_COUNT_SCAN_MAX);
  if (ids.length === 0) return 0;
  const queued = new Set(ids);
  const accessible = await elFindByIds<BasicStoreBase>(context, user, ids, { indices: READ_ENTITIES_INDICES, baseData: true }) as BasicStoreBase[];
  return new Set(accessible.map((entity) => entity.internal_id).filter((id) => queued.has(id))).size;
};

// the similarity count of a caller without the bypass covers this many links at most, the most recently computed
const SIMILARITY_COUNT_SCAN_MAX = 10000;

/** Similarity links: every stored link for an account that bypasses data restrictions, the links between two entities the caller can access otherwise. */
const countGraphSimilarityLinks = async (context: AuthContext, user: AuthUser): Promise<number> => {
  if (isBypassUser(user)) return countSimilarityRows(context, user);
  const links = await listRecentSimilarityEndpoints(context, user, SIMILARITY_COUNT_SCAN_MAX);
  if (links.length === 0) return 0;
  const endpointIds = Array.from(new Set(links.flatMap((link) => [link.similarity_entity_id, link.similarity_target_id])));
  const accessible = await elFindByIds<BasicStoreBase>(context, user, endpointIds, { indices: READ_ENTITIES_INDICES, baseData: true }) as BasicStoreBase[];
  const accessibleIds = new Set(accessible.map((entity) => entity.internal_id));
  return links.filter((link) => accessibleIds.has(link.similarity_entity_id) && accessibleIds.has(link.similarity_target_id)).length;
};

export const getGraphAnalyticsStatus = async (context: AuthContext, user: AuthUser) => {
  const state = await redisGraphAnalyticsGetState();
  const [pending, similarityDocuments, clusters] = await Promise.all([
    countGraphAnalyticsPendingEntities(context, user),
    countGraphSimilarityLinks(context, user),
    // the clusters the caller sees in the list: at least one member they can access
    findGraphClusters(context, user, { first: 1 }),
  ]);
  return {
    manager_enabled: booleanConf('graph_analytics_manager:enabled', true),
    pending_entities: pending,
    last_incremental_run: parseStateDate(state[GRAPH_STATE_LAST_INCREMENTAL_RUN]),
    full_pass_in_progress: isFullPassInProgress(state),
    last_full_pass_started_at: parseStateDate(state[GRAPH_STATE_FULL_PASS_STARTED_AT]),
    last_full_pass_completed_at: parseStateDate(state[GRAPH_STATE_FULL_PASS_COMPLETED_AT]),
    last_full_pass_ended_at: lastFullPassEndedAt(state),
    next_full_pass_at: computeNextFullPassAt(state, getGraphAnalyticsComputeConfig()),
    similarity_documents: similarityDocuments,
    clusters_count: clusters.pageInfo.globalCount,
    analytics_process_active: isAnalyticsProcessActive(state),
    analytics_process_last_run_at: parseStateDate(state[GRAPH_STATE_ANALYTICS_LAST_RUN_AT]),
    analytics_process_last_run_id: state[GRAPH_STATE_ANALYTICS_LAST_RUN_ID] ?? null,
    analytics_process_version: state[GRAPH_STATE_ANALYTICS_VERSION] ?? null,
  };
};

/** Next entities waiting for a recompute, in processing order, restricted to the ones the caller can access. */
export const findGraphAnalyticsPendingEntities = async (context: AuthContext, user: AuthUser, first?: number | null) => {
  const limit = clamp(first, 25, 1, PENDING_ENTITIES_MAX);
  const ids = await redisGraphAnalyticsPendingIds(PENDING_SCAN_MAX);
  const found: StoreEntity[] = [];
  const seen = new Set<string>();
  for (let start = 0; start < ids.length && found.length < limit; start += PENDING_SCAN_CHUNK) {
    const chunk = ids.slice(start, start + PENDING_SCAN_CHUNK);
    const accessible = await accessibleMap<StoreEntity>(context, user, chunk);
    chunk.forEach((id) => {
      const entity = accessible[id];
      if (!entity || seen.has(entity.internal_id) || found.length >= limit) return;
      seen.add(entity.internal_id);
      found.push(entity);
    });
  }
  return found;
};

/** Queue entities for a recompute at the next manager tick, ahead of the backlog (only the ones the caller can access). */
export const requestGraphAnalyticsRecompute = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  // refused rather than cut: the caller must know that every entity it asked for is queued
  if (ids.length > RECOMPUTE_MAX_IDS) {
    throw FunctionalError('Too many entities to recompute in one request', { count: ids.length, max: RECOMPUTE_MAX_IDS });
  }
  const accessible = await accessibleMap<StoreEntity>(context, user, ids);
  const accessibleIds = Object.values(accessible).map((e) => e.internal_id);
  const uniqueIds = Array.from(new Set(accessibleIds));
  await redisGraphAnalyticsMarkPriority(uniqueIds);
  return uniqueIds.length;
};

export const recordGraphAnalyticsPivot = () => {
  addGraphAnalyticsPivotCount();
  return true;
};
// endregion
