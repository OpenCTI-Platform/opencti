import conf, { booleanConf } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreEntity, BasicStoreObject, BasicStoreRelation, StoreEntity } from '../../types/store';
import { elAggregationSearch, elCount, elFindByIds, elHistogramCount, elList } from '../../database/engine';
import { fullRelationsList, pageEntitiesConnection, pageRelationsConnection, storeLoadById } from '../../database/middleware-loader';
import { createRelation } from '../../database/middleware';
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
import { GRAPH_ANALYTICS_MANAGER_USER, isBypassUser } from '../../utils/access';
import { redisGraphAnalyticsGetState, redisGraphAnalyticsMarkPriority, redisGraphAnalyticsPendingCount, redisGraphAnalyticsSetState } from '../../database/redis';
import { addGraphAnalyticsPivotCount, addGraphClusterPromotionCount, addGraphSimilarityQueryCount } from '../../manager/telemetryManager';
import { addGrouping } from '../grouping/grouping-domain';
import { addCampaign } from '../../domain/campaign';
import { RELATION_COVERED } from '../securityCoverage/securityCoverage-types';
import { addWorkspace, findById as findWorkspaceById, workspaceEditField } from '../workspace/workspace-domain';
import { isRelationConsistent } from '../../utils/modelConsistency';
import { nowTime } from '../../utils/format';
import { getGraphAnalyticsComputeConfig, isFullPassInProgress, loadFeatureProfilesBatched, writeRunMetrics } from './graphAnalytics-compute';
import { computeSimilarityScore } from './graphAnalytics-scoring';
import {
  addClusterPromotion,
  countSimilarityRows,
  finalizeClusteringRun,
  GRAPH_METRICS_ENTITY_INDICES,
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
const MATRIX_MAX_ENTITIES: number = conf.get('graph_analytics:matrix_max_entities') ?? 25;
const CLUSTER_LIST_MAX_BUCKETS = 10000;
const PROMOTION_MAX_MEMBERS = 500;
const INVESTIGATION_MAX_ELEMENTS = 2000;
const UPSERT_MAX_METRICS = 5000;
const UPSERT_MAX_CLUSTERS = 1000;
const EDGES_MAX_PAGE = 5000;

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
  const rows = await listSimilarityRows(context, user, entity.internal_id, Math.min(first * 4 + 20, 500));
  const typedRows = rows.filter((row) => matchesEntityTypes(row.similarity_target_type, args.entityTypes));
  const targets = await accessibleMap<BasicStoreEntity>(context, user, typedRows.map((r) => r.similarity_target_id));
  const candidates = typedRows.flatMap((row) => (targets[row.similarity_target_id] ? [{ row, target: targets[row.similarity_target_id] }] : []));
  const profiles = await loadFeatureProfilesBatched(
    context,
    user,
    [entity, ...candidates.map((c) => c.target)].map((e) => ({ id: e.internal_id, entity_type: e.entity_type })),
    getGraphAnalyticsComputeConfig(),
    true,
  );
  const profilesById = new Map(profiles.map((p) => [p.id, p]));
  const source = profilesById.get(entity.internal_id);
  const scored = candidates.flatMap(({ row, target }) => {
    const profile = profilesById.get(target.internal_id);
    if (!source || !profile || profile.kind !== source.kind) return [];
    const score = computeSimilarityScore(source, profile);
    if (score.shared_count === 0 || score.score < minScore) return [];
    return [{ row, target, score }];
  });
  scored.sort((x, y) => (y.score.score - x.score.score)
    || (y.score.shared_count - x.score.shared_count)
    || x.target.internal_id.localeCompare(y.target.internal_id));
  const evidenceIds = scored.flatMap(({ score }) => Object.values(score.shared).flat() as string[]);
  const evidence = await accessibleMap<BasicStoreEntity>(context, user, evidenceIds);
  const visibleRows = scored.flatMap(({ row, target, score }) => {
    const families = GRAPH_FEATURE_FAMILIES
      .map((family) => ({ family, entities: (score.shared[family] ?? []).map((id) => evidence[id]).filter(Boolean) }))
      .filter((f) => f.entities.length > 0);
    if (families.length === 0) return [];
    return [{ row, target, score, families }];
  });
  const coverages = await findSecurityCoverages(context, user, visibleRows.map((v) => v.target.internal_id));
  const nodes = visibleRows
    .filter((v) => !args.onlyWithSecurityCoverage || coverages.has(v.target.internal_id))
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
  return buildConnection(nodes, nodes.length, visibleRows.length > nodes.length);
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
  return elList<BasicStoreEntity>(context, user, READ_ENTITIES_INDICES, {
    types: args.types && args.types.length > 0 ? args.types : [ABSTRACT_STIX_CORE_OBJECT],
    filters: args.filters ?? undefined,
    orderBy: `${GRAPH_METRICS_ATTRIBUTE}.degree`,
    orderMode: OrderingMode.Desc,
    first: limit,
    maxSize: limit,
  });
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
      const comparable = a && b && a.kind === b.kind;
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

/** Number of cluster members visible to the caller (and matching optional member filters), per cluster. */
const visibleMembersPerCluster = async (
  context: AuthContext,
  user: AuthUser,
  kinds?: GraphClusterKind[] | null,
  memberFilters?: InputMaybe<FilterGroup>,
): Promise<Map<string, number>> => {
  // The aggregation filters on raw metric fields (no filter key), so the member filters are checked and converted here
  const convertedMemberFilters = memberFilters
    ? await checkAndConvertFilters(context, user, memberFilters, user.id, filtersIdsFinder)
    : undefined;
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: [
      { key: [`${GRAPH_METRICS_ATTRIBUTE}.cluster_id`], values: [], operator: FilterOperator.NotNil },
      ...(kinds && kinds.length > 0 ? [{ key: [`${GRAPH_METRICS_ATTRIBUTE}.cluster_kind`], values: kinds }] : []),
    ],
    filterGroups: convertedMemberFilters ? [convertedMemberFilters] : [],
  };
  const aggregations = await elAggregationSearch(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters, noFiltersChecking: true }, {
    clusters: { terms: { field: `${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword`, size: CLUSTER_LIST_MAX_BUCKETS } },
  });
  const counts = new Map<string, number>();
  (aggregations.clusters?.buckets ?? []).forEach((bucket: any) => counts.set(String(bucket.key), bucket.doc_count));
  return counts;
};

const countVisibleMembers = async (context: AuthContext, user: AuthUser, clusterId: string) => {
  return elCount(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters: clusterMembersFilter(clusterId) });
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

/** Clusters having at least one member visible to the caller; members_count is the visible count. */
export const findGraphClusters = async (context: AuthContext, user: AuthUser, args: GraphClustersArgs) => {
  const visible = await visibleMembersPerCluster(context, user, args.kinds, args.memberFilters);
  if (visible.size === 0) return buildConnection([], 0);
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: [
      ...(args.kinds && args.kinds.length > 0 ? [{ key: ['cluster_kind'], values: args.kinds }] : []),
      ...(args.sources && args.sources.length > 0 ? [{ key: ['cluster_source'], values: args.sources }] : []),
    ],
    filterGroups: args.filters ? [args.filters] : [],
  };
  const connection = await pageEntitiesConnection<BasicStoreEntityGraphCluster>(context, user, [ENTITY_TYPE_GRAPH_CLUSTER], {
    ids: Array.from(visible.keys()),
    first: clamp(args.first, 25, 1, 500),
    after: args.after,
    search: args.search,
    orderBy: args.orderBy ?? 'members_count',
    orderMode: args.orderMode ?? OrderingMode.Desc,
    filters,
    indices: [READ_INDEX_INTERNAL_OBJECTS],
  });
  connection.edges.forEach((edge) => {
    edge.node.members_count = visible.get(edge.node.internal_id.toLowerCase()) ?? visible.get(edge.node.internal_id) ?? 0;
  });
  return connection;
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

/** Cumulative number of visible members over time, by member creation date in the platform. */
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
  const baseline = await elCount(context, user, GRAPH_METRICS_ENTITY_INDICES, { types: [ABSTRACT_STIX_CORE_OBJECT], filters, endDate: startDate.toISOString(), dateAttribute: 'created_at' });
  const histogram = await elHistogramCount(context, user, GRAPH_METRICS_ENTITY_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    filters,
    field: 'created_at',
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

const loadVisibleMemberIds = async (context: AuthContext, user: AuthUser, clusterId: string, max: number) => {
  const members = await elList<BasicStoreEntity>(context, user, GRAPH_METRICS_ENTITY_INDICES, {
    types: [ABSTRACT_STIX_CORE_OBJECT],
    filters: clusterMembersFilter(clusterId),
    baseData: true,
    first: Math.min(max, 1000),
    maxSize: max,
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
  const members = await loadVisibleMemberIds(context, user, cluster.internal_id, PROMOTION_MAX_MEMBERS);
  const featureIds = input.include_features
    ? (await graphClusterFeatures(context, user, cluster)).flatMap((f) => f.entities.map((e) => e.internal_id))
    : [];
  const baseInput = {
    name: input.name,
    description: input.description ?? '',
    createdBy: input.createdBy ?? undefined,
    objectMarking: input.objectMarking ?? [],
  };
  let created: BasicStoreEntity;
  if (input.target === GraphClusterPromotionTarget.Grouping) {
    const objects = Array.from(new Set([...members.map((m) => m.internal_id), ...featureIds]));
    created = await addGrouping(context, user, { ...baseInput, context: 'suspicious-activity', objects }) as unknown as BasicStoreEntity;
  } else {
    created = await addCampaign(context, user, baseInput) as BasicStoreEntity;
    const featureEntities = await accessibleMap<BasicStoreEntity>(context, user, featureIds);
    const targets = [...members, ...Object.values(featureEntities)];
    for (let i = 0; i < targets.length; i += 1) {
      const target = targets[i];
      const relationshipType = await isRelationConsistent(context, user, RELATION_USES, created, target) ? RELATION_USES : RELATION_RELATED_TO;
      if (await isRelationConsistent(context, user, relationshipType, created, target)) {
        await createRelation(context, user, {
          fromId: created.internal_id,
          toId: target.internal_id,
          relationship_type: relationshipType,
          objectMarking: input.objectMarking ?? [],
          createdBy: input.createdBy ?? undefined,
        });
      }
    }
  }
  await addClusterPromotion(context, cluster, created.internal_id);
  addGraphClusterPromotionCount();
  return created;
};

export const addGraphClusterToInvestigation = async (context: AuthContext, user: AuthUser, id: string, investigationId?: string | null) => {
  const cluster = await loadClusterOrFail(context, user, id);
  const members = await loadVisibleMemberIds(context, user, cluster.internal_id, INVESTIGATION_MAX_ELEMENTS);
  const features = await graphClusterFeatures(context, user, cluster);
  const ids = Array.from(new Set([...members.map((m) => m.internal_id), ...features.flatMap((f) => f.entities.map((e) => e.internal_id))]))
    .slice(0, INVESTIGATION_MAX_ELEMENTS);
  addGraphAnalyticsPivotCount();
  if (investigationId) {
    const workspace = await findWorkspaceById(context, user, investigationId);
    if (!workspace || workspace.type !== 'investigation') {
      throw FunctionalError('Investigation not found', { id: investigationId });
    }
    return workspaceEditField(context, user, investigationId, [{ key: 'investigated_entities_ids', value: ids, operation: 'add' as any }]);
  }
  return addWorkspace(context, user, { type: 'investigation', name: `${cluster.name} (${nowTime()})`, investigated_entities_ids: ids });
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

/** Compact edge export (ids and types only) for the opencti-analytics process, computed as the caller. */
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
  return {
    pageInfo: connection.pageInfo,
    edges: connection.edges.map((edge) => ({
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
  const { updated, skipped } = await writeRunMetrics(context, user, input.run_id, input.metrics.map((metric) => ({
    entity_id: metric.entity_id,
    cluster_id: metric.cluster_id ?? null,
    cluster_kind: (metric.cluster_kind as GraphClusterKind | null | undefined) ?? null,
    cluster_size: metric.cluster_size ?? null,
    betweenness_approx: metric.betweenness_approx ?? null,
  })));
  const upserted = await upsertGraphClusters(context, user, clusters.map((cluster) => ({
    cluster_id: cluster.cluster_id,
    cluster_kind: cluster.cluster_kind as GraphClusterKind,
    members_count: cluster.members_count,
    representative_ids: cluster.representative_ids.slice(0, 20),
    features: (cluster.features ?? []).map((f) => ({ family: f.family as GraphFeatureFamily, ids: f.ids.slice(0, 50) })),
  })), 'analytics', input.run_id);
  let removed: string[] = [];
  const state: Record<string, string> = { [GRAPH_STATE_ANALYTICS_LAST_RUN_ID]: input.run_id };
  if (input.process_version) state[GRAPH_STATE_ANALYTICS_VERSION] = input.process_version;
  if (input.complete) {
    removed = await finalizeClusteringRun(context, GRAPH_ANALYTICS_MANAGER_USER, input.run_id);
    state[GRAPH_STATE_ANALYTICS_LAST_RUN_AT] = new Date().toISOString();
  }
  await redisGraphAnalyticsSetState(state);
  return {
    run_id: input.run_id,
    updated_entities: updated,
    skipped_entities: skipped,
    upserted_clusters: upserted,
    removed_clusters: removed.length,
  };
};

export const getGraphAnalyticsStatus = async (context: AuthContext, user: AuthUser) => {
  const state = await redisGraphAnalyticsGetState();
  const [pending, similarityDocuments, clustersCount] = await Promise.all([
    redisGraphAnalyticsPendingCount(),
    countSimilarityRows(context, user),
    elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_GRAPH_CLUSTER] }),
  ]);
  return {
    manager_enabled: booleanConf('graph_analytics_manager:enabled', true),
    pending_entities: pending,
    last_incremental_run: parseStateDate(state[GRAPH_STATE_LAST_INCREMENTAL_RUN]),
    full_pass_in_progress: isFullPassInProgress(state),
    last_full_pass_started_at: parseStateDate(state[GRAPH_STATE_FULL_PASS_STARTED_AT]),
    last_full_pass_completed_at: parseStateDate(state[GRAPH_STATE_FULL_PASS_COMPLETED_AT]),
    similarity_documents: similarityDocuments,
    clusters_count: clustersCount,
    analytics_process_active: isAnalyticsProcessActive(state),
    analytics_process_last_run_at: parseStateDate(state[GRAPH_STATE_ANALYTICS_LAST_RUN_AT]),
    analytics_process_last_run_id: state[GRAPH_STATE_ANALYTICS_LAST_RUN_ID] ?? null,
    analytics_process_version: state[GRAPH_STATE_ANALYTICS_VERSION] ?? null,
  };
};

/** Queue entities for a recompute at the next manager tick, ahead of the backlog (only the ones the caller can access). */
export const requestGraphAnalyticsRecompute = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  const accessible = await accessibleMap<StoreEntity>(context, user, ids.slice(0, 1000));
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
