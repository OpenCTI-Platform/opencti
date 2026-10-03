import { v5 as uuidv5 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import { computeQueryIndices, elAggregationSearch, elBulk, elCount, elFindByIds, elList, elRawDeleteByQuery, elRawSearch, elRawUpdateByQuery } from '../../database/engine';
import { buildRelationsFilter } from '../../database/middleware-loader';
import {
  INDEX_GRAPH_SIMILARITY,
  INDEX_INTERNAL_OBJECTS,
  READ_INDEX_GRAPH_SIMILARITY,
  READ_INDEX_INTERNAL_OBJECTS,
  READ_INDEX_STIX_CYBER_OBSERVABLES,
  READ_INDEX_STIX_DOMAIN_OBJECTS,
} from '../../database/utils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, OPENCTI_NAMESPACE } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { generateStandardId } from '../../schema/identifier';
import { getParentTypes } from '../../schema/schemaUtils';
import { schemaTypesDefinition } from '../../schema/schema-types';
import { ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { DatabaseError } from '../../config/errors';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import {
  type BasicStoreEntityGraphCluster,
  ENTITY_TYPE_GRAPH_CLUSTER,
  ENTITY_TYPE_GRAPH_SIMILARITY,
  GRAPH_METRICS_ATTRIBUTE,
  type GraphClusterFeature,
  type GraphClusterKind,
  type GraphClusterSource,
  type GraphMetrics,
  type GraphMetricsDegreeByType,
  type GraphSimilarityDocument,
} from './graphAnalytics-types';
import type { GraphSimilarityScore } from './graphAnalytics-scoring';
import { buildGraphClusterName } from './graphAnalytics-clustering';

export const DEGREE_RELATIONSHIP_TYPES = [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP];
export const GRAPH_METRICS_ENTITY_INDICES = [READ_INDEX_STIX_DOMAIN_OBJECTS, READ_INDEX_STIX_CYBER_OBSERVABLES];

// Stable script sources: field names travel as parameters so the engine compiles each script once.
const GRAPH_METRICS_UPDATE_SCRIPT = 'if (ctx._source.x_opencti_graph_metrics == null) { ctx._source.x_opencti_graph_metrics = [:]; }'
  + ' for (entry in params.metrics.entrySet()) {'
  + ' if (entry.getValue() == null) { ctx._source.x_opencti_graph_metrics.remove(entry.getKey()); }'
  + ' else { ctx._source.x_opencti_graph_metrics[entry.getKey()] = entry.getValue(); } }';
const GRAPH_METRICS_CLEAR_FIELDS_SCRIPT = 'if (ctx._source.x_opencti_graph_metrics != null) {'
  + ' for (key in params.fields) { ctx._source.x_opencti_graph_metrics.remove(key); } }';
// Appends on the stored document, so concurrent promotions of one cluster all remain linked
const CLUSTER_ADD_PROMOTION_SCRIPT = 'if (ctx._source.promoted_to_ids == null) { ctx._source.promoted_to_ids = [params.id]; }'
  + ' else if (!ctx._source.promoted_to_ids.contains(params.id)) { ctx._source.promoted_to_ids.add(params.id); }'
  + ' else { ctx.op = \'noop\'; }';
// Metrics owned by a clustering run (platform clustering or opencti-analytics process)
const RUN_METRIC_FIELDS = ['cluster_id', 'cluster_size', 'cluster_kind', 'betweenness_approx', 'run_id', 'cluster_joined_at'];
// A run writes its metrics as pending_<field> (null included) and they replace the live ones when the run completes,
// so readers never see a partially applied run, whether it completes, fails or is cancelled.
const STAGED_RUN_FIELDS = ['cluster_id', 'cluster_size', 'cluster_kind', 'betweenness_approx'];
const PENDING_PREFIX = 'pending_';
const PENDING_RUN_ID = `${PENDING_PREFIX}run_id`;
const GRAPH_METRICS_STAGE_SCRIPT = 'if (ctx._source.x_opencti_graph_metrics == null) { ctx._source.x_opencti_graph_metrics = [:]; }'
  + ' for (entry in params.metrics.entrySet()) { ctx._source.x_opencti_graph_metrics[entry.getKey()] = entry.getValue(); }';
const GRAPH_METRICS_PROMOTE_SCRIPT = 'def m = ctx._source.x_opencti_graph_metrics;'
  + ' if (m.containsKey(params.prefix + \'cluster_id\')) { def next = m[params.prefix + \'cluster_id\'];'
  + ' if (next == null) { m.remove(\'cluster_joined_at\'); }'
  + ' else if (m.cluster_id != next || m.cluster_joined_at == null) { m.cluster_joined_at = params.now; } }'
  + ' for (field in params.fields) { def key = params.prefix + field; if (m.containsKey(key)) { def value = m.remove(key);'
  + ' if (value == null) { m.remove(field); } else { m[field] = value; } } }'
  + ' m.run_id = m.remove(params.prefix + \'run_id\');';
const GRAPH_METRICS_DROP_PENDING_SCRIPT = 'def m = ctx._source.x_opencti_graph_metrics;'
  + ' for (field in params.fields) { m.remove(params.prefix + field); } m.remove(params.prefix + \'run_id\');';

const BULK_CHUNK = 500;

const chunk = <T>(items: T[], size: number): T[][] => {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
};

// region canonical entity types
let canonicalTypes: Map<string, string> | undefined;
/**
 * Keyword fields are normalized in lower case: map a value back to the concrete Stix Core Object type it stands for,
 * or null for abstract types and unknown values.
 */
export const resolveConcreteEntityType = (value: string): string | null => {
  if (!canonicalTypes) {
    canonicalTypes = new Map();
    [...schemaTypesDefinition.get(ABSTRACT_STIX_DOMAIN_OBJECT), ...schemaTypesDefinition.get(ABSTRACT_STIX_CYBER_OBSERVABLE)]
      .forEach((type) => canonicalTypes?.set(type.toLowerCase(), type));
  }
  return canonicalTypes.get(value.toLowerCase()) ?? null;
};
// endregion

// region degree metrics
export interface DegreeMetrics {
  degree: number;
  degree_by_type: GraphMetricsDegreeByType[];
}

/** Number of stix core relationships and sightings per entity, split by relationship type. */
export const computeDegreeMetrics = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<Map<string, DegreeMetrics>> => {
  const result = new Map<string, DegreeMetrics>();
  ids.forEach((id) => result.set(id, { degree: 0, degree_by_type: [] }));
  if (ids.length === 0) return result;
  const lowerToId = new Map(ids.map((id) => [id.toLowerCase(), id]));
  const indices = computeQueryIndices(undefined, DEGREE_RELATIONSHIP_TYPES, false) as string[];
  const { filters } = buildRelationsFilter(DEGREE_RELATIONSHIP_TYPES, { fromOrToId: ids });
  const aggregations = await elAggregationSearch(context, user, indices, { types: DEGREE_RELATIONSHIP_TYPES, filters, noFiltersChecking: true }, {
    connections: {
      nested: { path: 'connections' },
      aggs: {
        selected: {
          filter: { terms: { 'connections.internal_id.keyword': ids } },
          aggs: {
            entities: {
              terms: { field: 'connections.internal_id.keyword', size: ids.length },
              aggs: {
                relationships: {
                  reverse_nested: {},
                  aggs: { types: { terms: { field: 'relationship_type.keyword', size: 200 } } },
                },
              },
            },
          },
        },
      },
    },
  });
  const buckets = aggregations.connections?.selected?.entities?.buckets ?? [];
  buckets.forEach((bucket: any) => {
    const id = lowerToId.get(String(bucket.key).toLowerCase());
    if (!id) return;
    const degreeByType = (bucket.relationships?.types?.buckets ?? [])
      .map((typeBucket: any) => ({ relationship_type: String(typeBucket.key), count: typeBucket.doc_count as number }))
      .sort((a: GraphMetricsDegreeByType, b: GraphMetricsDegreeByType) => (b.count - a.count) || a.relationship_type.localeCompare(b.relationship_type));
    result.set(id, { degree: bucket.relationships?.doc_count ?? 0, degree_by_type: degreeByType });
  });
  return result;
};
// endregion

// region entity metrics writes (no stream event, no updated_at change)
export interface GraphMetricsUpdate {
  id: string;
  index: string;
  metrics: Partial<Record<keyof GraphMetrics, unknown>>;
}

const bulkUpdateGraphMetrics = async (context: AuthContext, updates: GraphMetricsUpdate[], source: string): Promise<number> => {
  let written = 0;
  const chunks = chunk(updates, BULK_CHUNK);
  for (let i = 0; i < chunks.length; i += 1) {
    const body = chunks[i].flatMap((update) => [
      { update: { _index: update.index, _id: update.id, retry_on_conflict: 5 } },
      { script: { source, lang: 'painless', params: { metrics: update.metrics } } },
    ]);
    await elBulk(context, { refresh: true, timeout: '5m', body });
    written += chunks[i].length;
  }
  return written;
};

export const writeGraphMetrics = async (context: AuthContext, updates: GraphMetricsUpdate[]): Promise<number> => {
  return bulkUpdateGraphMetrics(context, updates, GRAPH_METRICS_UPDATE_SCRIPT);
};

/** Stage the metrics of a clustering run: they only become visible when the run completes. */
export const stageRunMetrics = async (context: AuthContext, runId: string, updates: GraphMetricsUpdate[]): Promise<number> => {
  const staged = updates.map((update) => {
    const metrics: Record<string, unknown> = { [PENDING_RUN_ID]: runId };
    STAGED_RUN_FIELDS.forEach((field) => {
      if (field in update.metrics) metrics[`${PENDING_PREFIX}${field}`] = update.metrics[field as keyof GraphMetrics] ?? null;
    });
    return { ...update, metrics: metrics as GraphMetricsUpdate['metrics'] };
  });
  return bulkUpdateGraphMetrics(context, staged, GRAPH_METRICS_STAGE_SCRIPT);
};

/** Make the staged metrics of a completed run the live ones, recording when an entity joined its cluster. */
const promoteRunMetrics = async (runId: string) => {
  await elRawUpdateByQuery({
    index: GRAPH_METRICS_ENTITY_INDICES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: {
        source: GRAPH_METRICS_PROMOTE_SCRIPT,
        lang: 'painless',
        params: { prefix: PENDING_PREFIX, fields: STAGED_RUN_FIELDS, now: new Date().toISOString() },
      },
      query: { term: { [`${GRAPH_METRICS_ATTRIBUTE}.${PENDING_RUN_ID}.keyword`]: runId } },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Graph analytics run metrics promotion fail', { cause: err });
  });
};

/** Metrics staged by runs that never completed (failed or cancelled) are dropped. */
const dropPendingMetricsNotFromRun = async (runId: string) => {
  await elRawUpdateByQuery({
    index: GRAPH_METRICS_ENTITY_INDICES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: GRAPH_METRICS_DROP_PENDING_SCRIPT, lang: 'painless', params: { prefix: PENDING_PREFIX, fields: STAGED_RUN_FIELDS } },
      query: {
        bool: {
          must: [{ exists: { field: `${GRAPH_METRICS_ATTRIBUTE}.${PENDING_RUN_ID}` } }],
          must_not: [{ term: { [`${GRAPH_METRICS_ATTRIBUTE}.${PENDING_RUN_ID}.keyword`]: runId } }],
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Graph analytics pending metrics cleanup fail', { cause: err });
  });
};

/** Load the documents (index and current metrics) of entities able to carry graph metrics. */
export const loadMetricsCarriers = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<BasicStoreBase[]> => {
  if (ids.length === 0) return [];
  return elFindByIds<BasicStoreBase>(context, user, ids, {
    indices: GRAPH_METRICS_ENTITY_INDICES,
    baseData: true,
    baseFields: [GRAPH_METRICS_ATTRIBUTE],
  }) as Promise<BasicStoreBase[]>;
};

/**
 * The latest completed clustering run owns cluster assignments and centrality: entities written by an older run
 * (moved out of every cluster, or out of the analyzed graph) are detached.
 */
export const clearRunMetricsNotFromRun = async (runId: string) => {
  await elRawUpdateByQuery({
    index: GRAPH_METRICS_ENTITY_INDICES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: GRAPH_METRICS_CLEAR_FIELDS_SCRIPT, lang: 'painless', params: { fields: RUN_METRIC_FIELDS } },
      query: {
        bool: {
          must: [{ exists: { field: `${GRAPH_METRICS_ATTRIBUTE}.run_id` } }],
          must_not: [{ term: { [`${GRAPH_METRICS_ATTRIBUTE}.run_id.keyword`]: runId } }],
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Graph analytics run metrics cleanup fail', { cause: err });
  });
};

/** Number of relationships of the given types touching each element (used to discard hub features). */
export const countRelationshipsPerElement = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  relationshipTypes: string[],
): Promise<Map<string, number>> => {
  const counts = new Map<string, number>();
  if (ids.length === 0) return counts;
  const lowerToId = new Map(ids.map((id) => [id.toLowerCase(), id]));
  const indices = computeQueryIndices(undefined, relationshipTypes, false) as string[];
  const { filters } = buildRelationsFilter(relationshipTypes, { fromOrToId: ids });
  const aggregations = await elAggregationSearch(context, user, indices, { types: relationshipTypes, filters, noFiltersChecking: true }, {
    connections: {
      nested: { path: 'connections' },
      aggs: {
        selected: {
          filter: { terms: { 'connections.internal_id.keyword': ids } },
          aggs: { elements: { terms: { field: 'connections.internal_id.keyword', size: ids.length } } },
        },
      },
    },
  });
  (aggregations.connections?.selected?.elements?.buckets ?? []).forEach((bucket: any) => {
    const id = lowerToId.get(String(bucket.key).toLowerCase());
    if (id) counts.set(id, bucket.doc_count);
  });
  return counts;
};
// endregion

// region similarity rows
const similarityRowId = (sourceId: string, targetId: string) => uuidv5(`graph-similarity:${sourceId}|${targetId}`, OPENCTI_NAMESPACE);

export const buildSimilarityRow = (
  source: { id: string; entity_type: string },
  target: { id: string; entity_type: string },
  score: GraphSimilarityScore,
  computedAt: string,
): GraphSimilarityDocument & Record<string, unknown> => {
  const internalId = similarityRowId(source.id, target.id);
  return {
    internal_id: internalId,
    standard_id: generateStandardId(ENTITY_TYPE_GRAPH_SIMILARITY, { similarity_entity_id: source.id, similarity_target_id: target.id }),
    entity_type: ENTITY_TYPE_GRAPH_SIMILARITY,
    base_type: 'ENTITY',
    parent_types: getParentTypes(ENTITY_TYPE_GRAPH_SIMILARITY),
    created_at: computedAt,
    updated_at: computedAt,
    similarity_entity_id: source.id,
    similarity_entity_type: source.entity_type,
    similarity_target_id: target.id,
    similarity_target_type: target.entity_type,
    similarity_score: score.score,
    similarity_jaccard: score.jaccard,
    similarity_structural: score.structural,
    similarity_shared: score.shared,
    similarity_computed_at: computedAt,
  };
};

const searchSimilarityRows = async (context: AuthContext, user: AuthUser, query: any, size: number, from = 0): Promise<GraphSimilarityDocument[]> => {
  const data = await elRawSearch(context, user, ENTITY_TYPE_GRAPH_SIMILARITY, {
    index: READ_INDEX_GRAPH_SIMILARITY,
    body: {
      from,
      size,
      query,
      sort: [{ similarity_score: 'desc' }, { 'similarity_target_id.keyword': 'asc' }],
    },
  });
  return (data.hits?.hits ?? []).map((hit: any) => hit._source as GraphSimilarityDocument);
};

export const listSimilarityRows = async (context: AuthContext, user: AuthUser, entityId: string, size: number, minScore = 0, from = 0) => {
  return searchSimilarityRows(context, user, {
    bool: {
      must: [{ term: { 'similarity_entity_id.keyword': entityId } }],
      filter: [{ range: { similarity_score: { gte: minScore } } }],
    },
  }, size, from);
};

export const listSimilarityRowsBetween = async (context: AuthContext, user: AuthUser, ids: string[]) => {
  if (ids.length === 0) return [];
  return searchSimilarityRows(context, user, {
    bool: {
      must: [
        { terms: { 'similarity_entity_id.keyword': ids } },
        { terms: { 'similarity_target_id.keyword': ids } },
      ],
    },
  }, ids.length * ids.length);
};

export const deleteSimilarityRowsForEntities = async (ids: string[]) => {
  const chunks = chunk(ids, 1000);
  for (let i = 0; i < chunks.length; i += 1) {
    await elRawDeleteByQuery({
      index: READ_INDEX_GRAPH_SIMILARITY,
      refresh: true,
      conflicts: 'proceed',
      body: {
        query: {
          bool: {
            should: [
              { terms: { 'similarity_entity_id.keyword': chunks[i] } },
              { terms: { 'similarity_target_id.keyword': chunks[i] } },
            ],
            minimum_should_match: 1,
          },
        },
      },
    }).catch((err: unknown) => {
      throw DatabaseError('Graph analytics similarity cleanup fail', { cause: err });
    });
  }
};

export interface ScoredTarget extends GraphSimilarityScore {
  target_id: string;
  target_type: string;
}

/**
 * Rows of `source` that the replacement does not rewrite: every outgoing row, and the incoming rows
 * Y -> source whose Y is no longer a scored candidate. Rows of scored candidates are overwritten in place.
 */
const deleteReplacedSimilarityRows = async (sourceId: string, scoredIds: string[]) => {
  await elRawDeleteByQuery({
    index: READ_INDEX_GRAPH_SIMILARITY,
    refresh: true,
    conflicts: 'proceed',
    body: {
      query: {
        bool: {
          should: [
            { term: { 'similarity_entity_id.keyword': sourceId } },
            {
              bool: {
                must: [{ term: { 'similarity_target_id.keyword': sourceId } }],
                must_not: [{ terms: { 'similarity_entity_id.keyword': scoredIds } }],
              },
            },
          ],
          minimum_should_match: 1,
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Graph analytics similarity cleanup fail', { cause: err });
  });
};

/**
 * Replace every row touching `source`. Rows are directional (A -> B lists B among the top-N of A),
 * the score being symmetric, B -> A is refreshed at the same time so B does not wait for its own recompute.
 * Rows Y -> A kept by Y for its own top-N are refreshed with the new score, or removed when A no longer qualifies.
 */
export const replaceSimilarityRows = async (
  context: AuthContext,
  user: AuthUser,
  source: { id: string; entity_type: string },
  scored: ScoredTarget[],
  topN: number,
) => {
  const computedAt = new Date().toISOString();
  const keep = scored.slice(0, topN);
  const keepIds = new Set(keep.map((k) => k.target_id));
  const scoredById = new Map(scored.map((s) => [s.target_id, s]));
  // only the incoming rows of scored candidates are refreshed, their number is bounded by the candidates limit
  const refreshableIds = scored.map((s) => s.target_id).filter((id) => !keepIds.has(id));
  const incoming = refreshableIds.length === 0 ? [] : await searchSimilarityRows(context, user, {
    bool: {
      must: [
        { term: { 'similarity_target_id.keyword': source.id } },
        { terms: { 'similarity_entity_id.keyword': refreshableIds } },
      ],
    },
  }, refreshableIds.length);
  await deleteReplacedSimilarityRows(source.id, Array.from(scoredById.keys()));
  const rows: Array<Record<string, unknown>> = [];
  keep.forEach((target) => {
    const targetRef = { id: target.target_id, entity_type: target.target_type };
    rows.push(buildSimilarityRow(source, targetRef, target, computedAt));
    rows.push(buildSimilarityRow(targetRef, source, target, computedAt));
  });
  incoming.forEach((row) => {
    const fresh = scoredById.get(row.similarity_entity_id);
    if (fresh) {
      rows.push(buildSimilarityRow({ id: row.similarity_entity_id, entity_type: row.similarity_entity_type }, source, fresh, computedAt));
    }
  });
  const chunks = chunk(rows, BULK_CHUNK);
  for (let i = 0; i < chunks.length; i += 1) {
    const body = chunks[i].flatMap((row) => [{ index: { _index: INDEX_GRAPH_SIMILARITY, _id: row.internal_id } }, row]);
    await elBulk(context, { refresh: true, timeout: '5m', body });
  }
  return { written: rows.length, kept: keep.length };
};

export const countSimilarityRows = async (context: AuthContext, user: AuthUser): Promise<number> => {
  return elCount(context, user, READ_INDEX_GRAPH_SIMILARITY, { types: [ENTITY_TYPE_GRAPH_SIMILARITY] });
};
// endregion

// region clusters
export interface GraphClusterWrite {
  cluster_id: string;
  cluster_kind: GraphClusterKind;
  members_count: number;
  representative_ids: string[];
  features: GraphClusterFeature[];
}

export const loadGraphClusters = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<BasicStoreEntityGraphCluster[]> => {
  if (ids.length === 0) return [];
  return elFindByIds<BasicStoreEntityGraphCluster>(context, user, ids, {
    indices: READ_INDEX_INTERNAL_OBJECTS,
    type: ENTITY_TYPE_GRAPH_CLUSTER,
  }) as Promise<BasicStoreEntityGraphCluster[]>;
};

/** Create or refresh cluster documents. Promotion links are preserved, the creation date too. */
export const upsertGraphClusters = async (
  context: AuthContext,
  user: AuthUser,
  clusters: GraphClusterWrite[],
  source: GraphClusterSource,
  runId: string,
): Promise<number> => {
  let upserted = 0;
  const chunks = chunk(clusters, BULK_CHUNK);
  for (let i = 0; i < chunks.length; i += 1) {
    const now = new Date().toISOString();
    const existing = await loadGraphClusters(context, user, chunks[i].map((c) => c.cluster_id));
    const existingById = new Map(existing.map((e) => [e.internal_id, e]));
    const body = chunks[i].flatMap((cluster): Array<Record<string, unknown>> => {
      const current = existingById.get(cluster.cluster_id);
      const fields = {
        name: buildGraphClusterName(cluster.cluster_kind, cluster.cluster_id),
        cluster_kind: cluster.cluster_kind,
        cluster_source: source,
        members_count: cluster.members_count,
        representative_ids: cluster.representative_ids,
        cluster_features: cluster.features,
        last_run_id: runId,
        last_computed_at: now,
        updated_at: now,
      };
      if (current) {
        return [{ update: { _index: current._index, _id: current.internal_id, retry_on_conflict: 5 } }, { doc: fields }];
      }
      const doc = {
        ...fields,
        internal_id: cluster.cluster_id,
        standard_id: generateStandardId(ENTITY_TYPE_GRAPH_CLUSTER, { cluster_id: cluster.cluster_id }),
        entity_type: ENTITY_TYPE_GRAPH_CLUSTER,
        base_type: 'ENTITY',
        parent_types: getParentTypes(ENTITY_TYPE_GRAPH_CLUSTER),
        cluster_id: cluster.cluster_id,
        promoted_to_ids: [],
        created_at: now,
      };
      return [{ index: { _index: INDEX_INTERNAL_OBJECTS, _id: cluster.cluster_id } }, doc];
    });
    await elBulk(context, { refresh: true, timeout: '5m', body });
    upserted += chunks[i].length;
  }
  return upserted;
};

/**
 * Finalize a clustering run: its staged entity metrics become the live ones, clusters not refreshed by the run are
 * deleted (whatever their source, only one source is active at a time) and entity assignments written by older runs
 * are detached.
 */
export const finalizeClusteringRun = async (context: AuthContext, user: AuthUser, runId: string): Promise<string[]> => {
  await promoteRunMetrics(runId);
  await dropPendingMetricsNotFromRun(runId);
  const stale = await elList<BasicStoreEntityGraphCluster>(context, user, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_GRAPH_CLUSTER],
    baseData: true,
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['last_run_id'], values: [runId], operator: FilterOperator.NotEq }],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  const chunks = chunk(stale, BULK_CHUNK);
  for (let i = 0; i < chunks.length; i += 1) {
    const body = chunks[i].map((c) => ({ delete: { _index: c._index, _id: c.internal_id } }));
    await elBulk(context, { refresh: true, body });
  }
  await clearRunMetricsNotFromRun(runId);
  return stale.map((s) => s.internal_id);
};

export const addClusterPromotion = async (context: AuthContext, cluster: BasicStoreEntityGraphCluster, promotedId: string) => {
  await elBulk(context, {
    refresh: true,
    body: [
      { update: { _index: cluster._index, _id: cluster.internal_id, retry_on_conflict: 5 } },
      { script: { source: CLUSTER_ADD_PROMOTION_SCRIPT, lang: 'painless', params: { id: promotedId } } },
    ],
  });
};
// endregion
