import { v5 as uuidv5 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase, BasicStoreRelation } from '../../types/store';
import { READ_ENTITIES_INDICES } from '../../database/utils';
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
import { ABSTRACT_STIX_CORE_OBJECT, ABSTRACT_STIX_CYBER_OBSERVABLE, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
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
import { buildDisplacedGraphClusterId, buildGraphClusterName, type ClusterLineageOverlap, matchClusterLineage } from './graphAnalytics-clustering';
import { SYSTEM_USER } from '../../utils/access';

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

// Relationships listed at once for restricted readers, and the most an entity may have to be counted for them
const VISIBLE_DEGREE_BATCH_RELATIONSHIPS = 20000;
export const VISIBLE_DEGREE_MAX_PER_ENTITY = 10000;

// Exact count for a batch whose relationships all fit in one listing
const countVisibleRelationships = async (context: AuthContext, user: AuthUser, ids: string[], result: Map<string, DegreeMetrics | null>) => {
  const measured = new Set(ids);
  const indices = computeQueryIndices(undefined, DEGREE_RELATIONSHIP_TYPES, false) as string[];
  const relations = await elList<BasicStoreRelation>(context, user, indices, {
    ...buildRelationsFilter(DEGREE_RELATIONSHIP_TYPES, { fromOrToId: ids }),
    baseData: true,
    first: 5000,
    // headroom for the relationships created between the count of the batch and this listing
    maxSize: 2 * VISIBLE_DEGREE_BATCH_RELATIONSHIPS,
  });
  const otherEnds = Array.from(new Set(relations.flatMap((relation) => [relation.fromId, relation.toId]).filter((id) => !measured.has(id))));
  const accessible = otherEnds.length > 0
    ? await elFindByIds<BasicStoreBase>(context, user, otherEnds, { indices: READ_ENTITIES_INDICES, baseData: true }) as BasicStoreBase[]
    : [];
  const visible = new Set([...ids, ...accessible.map((element) => element.internal_id)]);
  const counts = new Map<string, Map<string, number>>();
  const count = (id: string, relationshipType: string) => {
    const byType = counts.get(id) ?? new Map<string, number>();
    byType.set(relationshipType, (byType.get(relationshipType) ?? 0) + 1);
    counts.set(id, byType);
  };
  relations.forEach((relation) => {
    if (!visible.has(relation.fromId) || !visible.has(relation.toId)) return;
    if (measured.has(relation.fromId)) count(relation.fromId, relation.relationship_type);
    if (measured.has(relation.toId) && relation.toId !== relation.fromId) count(relation.toId, relation.relationship_type);
  });
  ids.forEach((id) => {
    const degreeByType = Array.from((counts.get(id) ?? new Map<string, number>()).entries())
      .map(([relationship_type, value]) => ({ relationship_type, count: value }))
      .sort((a, b) => (b.count - a.count) || a.relationship_type.localeCompare(b.relationship_type));
    result.set(id, { degree: degreeByType.reduce((sum, entry) => sum + entry.count, 0), degree_by_type: degreeByType });
  });
};

/**
 * Degree as a restricted reader may know it: a relationship only counts when the reader can read it and can also
 * access the entity at its other end, like the neighborhood summary. The measured entities are the reader's own.
 * The relationships the reader can read are first counted per entity: entities are then grouped in batches listed in
 * full, and an entity with more than VISIBLE_DEGREE_MAX_PER_ENTITY of them gets no degree (null) instead of a partial one.
 */
export const computeVisibleDegreeMetrics = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<Map<string, DegreeMetrics | null>> => {
  const result = new Map<string, DegreeMetrics | null>();
  if (ids.length === 0) return result;
  const readable = await computeDegreeMetrics(context, user, ids);
  const batches: string[][] = [];
  let batch: string[] = [];
  let batchRelationships = 0;
  ids.forEach((id) => {
    const count = readable.get(id)?.degree ?? 0;
    if (count === 0) {
      result.set(id, { degree: 0, degree_by_type: [] });
      return;
    }
    if (count > VISIBLE_DEGREE_MAX_PER_ENTITY) {
      result.set(id, null);
      return;
    }
    if (batch.length > 0 && batchRelationships + count > VISIBLE_DEGREE_BATCH_RELATIONSHIPS) {
      batches.push(batch);
      batch = [];
      batchRelationships = 0;
    }
    batch.push(id);
    batchRelationships += count;
  });
  if (batch.length > 0) batches.push(batch);
  for (let i = 0; i < batches.length; i += 1) {
    await countVisibleRelationships(context, user, batches[i], result);
  }
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
const promoteRunMetrics = async (runId: string, publishedAt: string) => {
  await elRawUpdateByQuery({
    index: GRAPH_METRICS_ENTITY_INDICES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: {
        source: GRAPH_METRICS_PROMOTE_SCRIPT,
        lang: 'painless',
        params: { prefix: PENDING_PREFIX, fields: STAGED_RUN_FIELDS, now: publishedAt },
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

// the current rows of the kept targets are read by pages of at most this many rows
const SIMILARITY_TARGET_ROWS_PAGE = 5000;

/** Current rows of each entity, an entity holding at most `topN` rows. */
const loadSimilarityRowsByEntity = async (context: AuthContext, user: AuthUser, ids: string[], topN: number) => {
  const rowsByEntity = new Map<string, GraphSimilarityDocument[]>();
  const chunks = chunk(ids, Math.max(1, Math.floor(SIMILARITY_TARGET_ROWS_PAGE / (topN + 1))));
  for (let i = 0; i < chunks.length; i += 1) {
    const rows = await searchSimilarityRows(context, user, {
      bool: { must: [{ terms: { 'similarity_entity_id.keyword': chunks[i] } }] },
    }, chunks[i].length * (topN + 1));
    rows.forEach((row) => {
      const entityRows = rowsByEntity.get(row.similarity_entity_id) ?? [];
      entityRows.push(row);
      rowsByEntity.set(row.similarity_entity_id, entityRows);
    });
  }
  return rowsByEntity;
};

// same order as the stored rows of an entity are read
const compareStoredSimilarity = (x: { id: string; score: number }, y: { id: string; score: number }) => (y.score - x.score) || x.id.localeCompare(y.id);

/**
 * Replace every row touching `source`. Rows are directional (A -> B lists B among the top-N of A); the score being
 * symmetric, B -> A is written at the same time when A ranks in the top-N of B, so B does not wait for its own
 * recompute, and the row it pushes out of that top-N is removed: no entity ever holds more than top-N rows.
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
  const keptTargetRows = await loadSimilarityRowsByEntity(context, user, Array.from(keepIds), topN);
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
  const evictedRowIds: string[] = [];
  keep.forEach((target) => {
    const targetRef = { id: target.target_id, entity_type: target.target_type };
    rows.push(buildSimilarityRow(source, targetRef, target, computedAt));
    const ranked = [
      ...(keptTargetRows.get(target.target_id) ?? [])
        .filter((row) => row.similarity_target_id !== source.id)
        .map((row) => ({ id: row.similarity_target_id, score: row.similarity_score })),
      { id: source.id, score: target.score },
    ].sort(compareStoredSimilarity);
    ranked.forEach((entry, index) => {
      if (index >= topN) {
        evictedRowIds.push(similarityRowId(target.target_id, entry.id));
      } else if (entry.id === source.id) {
        rows.push(buildSimilarityRow(targetRef, source, target, computedAt));
      }
    });
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
  if (evictedRowIds.length > 0) {
    await elRawDeleteByQuery({
      index: READ_INDEX_GRAPH_SIMILARITY,
      refresh: true,
      conflicts: 'proceed',
      body: { query: { ids: { values: evictedRowIds } } },
    }).catch((err: unknown) => {
      throw DatabaseError('Graph analytics similarity cleanup fail', { cause: err });
    });
  }
  return { written: rows.length, kept: keep.length, evicted: evictedRowIds.length };
};

export const countSimilarityRows = async (context: AuthContext, user: AuthUser): Promise<number> => {
  return elCount(context, user, READ_INDEX_GRAPH_SIMILARITY, { types: [ENTITY_TYPE_GRAPH_SIMILARITY] });
};

/** Both ends of the most recently computed similarity rows. */
export const listRecentSimilarityEndpoints = async (
  context: AuthContext,
  user: AuthUser,
  size: number,
): Promise<Array<Pick<GraphSimilarityDocument, 'similarity_entity_id' | 'similarity_target_id'>>> => {
  const data = await elRawSearch(context, user, ENTITY_TYPE_GRAPH_SIMILARITY, {
    index: READ_INDEX_GRAPH_SIMILARITY,
    body: {
      size,
      _source: ['similarity_entity_id', 'similarity_target_id'],
      query: { match_all: {} },
      sort: [{ similarity_computed_at: 'desc' }, { 'similarity_entity_id.keyword': 'asc' }, { 'similarity_target_id.keyword': 'asc' }],
    },
  });
  return (data.hits?.hits ?? []).map((hit: any) => hit._source);
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

// A cluster document never published yet: only its staged fields, published when its run completes
const buildGraphClusterSkeleton = (clusterId: string, now: string, pending: Record<string, unknown>) => ({
  pending_cluster: pending,
  internal_id: clusterId,
  standard_id: generateStandardId(ENTITY_TYPE_GRAPH_CLUSTER, { cluster_id: clusterId }),
  entity_type: ENTITY_TYPE_GRAPH_CLUSTER,
  base_type: 'ENTITY',
  parent_types: getParentTypes(ENTITY_TYPE_GRAPH_CLUSTER),
  cluster_id: clusterId,
  promoted_to_ids: [],
  created_at: now,
});

/**
 * Stage cluster documents of a run in `pending_cluster`, published when the run completes. A cluster created by the
 * run is a skeleton without published fields until then. Promotion links are preserved, the creation date too.
 */
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
      const pending = {
        run_id: runId,
        name: buildGraphClusterName(cluster.cluster_kind, cluster.cluster_id),
        cluster_kind: cluster.cluster_kind,
        cluster_source: source,
        members_count: cluster.members_count,
        representative_ids: cluster.representative_ids,
        cluster_features: cluster.features,
        computed_at: now,
      };
      if (current) {
        return [{ update: { _index: current._index, _id: current.internal_id, retry_on_conflict: 5 } }, { doc: { pending_cluster: pending } }];
      }
      return [{ index: { _index: INDEX_INTERNAL_OBJECTS, _id: cluster.cluster_id } }, buildGraphClusterSkeleton(cluster.cluster_id, now, pending)];
    });
    await elBulk(context, { refresh: true, timeout: '5m', body });
    upserted += chunks[i].length;
  }
  return upserted;
};

const CLUSTER_PUBLISH_SCRIPT = 'def p = ctx._source.remove(\'pending_cluster\');'
  + ' for (entry in p.entrySet()) { def key = entry.getKey();'
  + ' if (key == \'run_id\') { ctx._source.last_run_id = entry.getValue(); }'
  + ' else if (key == \'computed_at\') { ctx._source.last_computed_at = entry.getValue(); ctx._source.updated_at = entry.getValue(); }'
  + ' else { ctx._source[key] = entry.getValue(); } }';
// a skeleton (cluster never published) staged by an interrupted run is removed, a published cluster keeps its fields
const CLUSTER_DROP_PENDING_SCRIPT = 'ctx._source.remove(\'pending_cluster\'); if (ctx._source.last_run_id == null) { ctx.op = \'delete\'; }';

const updateRunClusters = async (source: string, query: Record<string, unknown>, failure: string) => {
  await elRawUpdateByQuery({
    index: READ_INDEX_INTERNAL_OBJECTS,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source, lang: 'painless' },
      query: { bool: { must: [{ term: { 'entity_type.keyword': ENTITY_TYPE_GRAPH_CLUSTER } }, query] } },
    },
  }).catch((err: unknown) => {
    throw DatabaseError(failure, { cause: err });
  });
};

const LINEAGE_PAGE_SIZE = 5000;
const PENDING_CLUSTER_FIELD = `${GRAPH_METRICS_ATTRIBUTE}.${PENDING_PREFIX}cluster_id`;
const RENAME_PENDING_CLUSTER_SCRIPT = 'def m = ctx._source.x_opencti_graph_metrics; def next = params.renames.get(m[params.field]);'
  + ' if (next == null) { ctx.op = \'noop\'; } else { m[params.field] = next; }';
const SET_PENDING_CLUSTER_SCRIPT = 'ctx._source.pending_cluster = params.pending';

/** Members of the run per (computed cluster, previous cluster) pair, and size of every computed cluster. */
const loadRunLineageOverlaps = async (context: AuthContext, runId: string): Promise<ClusterLineageOverlap[]> => {
  const overlaps: ClusterLineageOverlap[] = [];
  let after: Record<string, unknown> | undefined;
  do {
    const data = await elRawSearch(context, SYSTEM_USER, ABSTRACT_STIX_CORE_OBJECT, {
      index: GRAPH_METRICS_ENTITY_INDICES,
      body: {
        size: 0,
        query: { bool: { must: [{ term: { [`${GRAPH_METRICS_ATTRIBUTE}.${PENDING_RUN_ID}.keyword`]: runId } }, { exists: { field: PENDING_CLUSTER_FIELD } }] } },
        aggs: {
          pairs: {
            composite: {
              size: LINEAGE_PAGE_SIZE,
              sources: [
                { next: { terms: { field: `${PENDING_CLUSTER_FIELD}.keyword` } } },
                { previous: { terms: { field: `${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword` } } },
              ],
              ...(after ? { after } : {}),
            },
          },
        },
      },
    });
    const buckets: any[] = data.aggregations?.pairs?.buckets ?? [];
    buckets.forEach((bucket) => overlaps.push({ next: String(bucket.key.next), previous: String(bucket.key.previous), members: bucket.doc_count }));
    after = buckets.length === LINEAGE_PAGE_SIZE ? data.aggregations?.pairs?.after_key : undefined;
  } while (after);
  return overlaps;
};

const countPublishedMembers = async (context: AuthContext, clusterIds: string[]): Promise<Map<string, number>> => {
  const sizes = new Map<string, number>();
  const chunks = chunk(clusterIds, 1000);
  for (let i = 0; i < chunks.length; i += 1) {
    const data = await elRawSearch(context, SYSTEM_USER, ABSTRACT_STIX_CORE_OBJECT, {
      index: GRAPH_METRICS_ENTITY_INDICES,
      body: {
        size: 0,
        query: { terms: { [`${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword`]: chunks[i] } },
        aggs: { clusters: { terms: { field: `${GRAPH_METRICS_ATTRIBUTE}.cluster_id.keyword`, size: chunks[i].length } } },
      },
    });
    (data.aggregations?.clusters?.buckets ?? []).forEach((bucket: any) => sizes.set(String(bucket.key), bucket.doc_count));
  }
  return sizes;
};

/**
 * Before publication, computed clusters continuing a previous cluster take its id (see matchClusterLineage): the
 * staged assignments of their members are renamed and the staged cluster fields move to the previous document; a
 * computed cluster displaced from its provisional id moves to a new document.
 */
const reconcileRunClusterIdentities = async (context: AuthContext, runId: string, assertRunLease: () => Promise<void>): Promise<number> => {
  const overlaps = await loadRunLineageOverlaps(context, runId);
  if (overlaps.length === 0) return 0;
  const previousSizes = await countPublishedMembers(context, Array.from(new Set(overlaps.map((overlap) => overlap.previous))));
  const renames = matchClusterLineage(overlaps, previousSizes, (computedId) => buildDisplacedGraphClusterId(computedId, runId));
  if (renames.size === 0) return 0;
  await assertRunLease();
  await elRawUpdateByQuery({
    index: GRAPH_METRICS_ENTITY_INDICES,
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: RENAME_PENDING_CLUSTER_SCRIPT, lang: 'painless', params: { renames: Object.fromEntries(renames), field: `${PENDING_PREFIX}cluster_id` } },
      query: {
        bool: {
          must: [
            { term: { [`${GRAPH_METRICS_ATTRIBUTE}.${PENDING_RUN_ID}.keyword`]: runId } },
            { terms: { [`${PENDING_CLUSTER_FIELD}.keyword`]: Array.from(renames.keys()) } },
          ],
        },
      },
    },
  }).catch((err: unknown) => {
    throw DatabaseError('Graph analytics cluster lineage fail', { cause: err });
  });
  // documents are read before any write: a computed cluster's staged fields are taken before another one replaces them
  const computed = await loadGraphClusters(context, SYSTEM_USER, Array.from(renames.keys()));
  const targets = await loadGraphClusters(context, SYSTEM_USER, Array.from(renames.values()));
  const targetsById = new Map(targets.map((cluster) => [cluster.internal_id, cluster]));
  const receivingIds = new Set(renames.values());
  const now = new Date().toISOString();
  const body = computed.flatMap((cluster): Array<Record<string, unknown>> => {
    const targetId = renames.get(cluster.internal_id);
    const pending = (cluster as unknown as { pending_cluster?: Record<string, unknown> }).pending_cluster;
    if (!targetId || !pending) return [];
    const moved = { ...pending, name: buildGraphClusterName(pending.cluster_kind as GraphClusterKind, targetId) };
    const target = targetsById.get(targetId);
    const write = target
      ? [{ update: { _index: target._index, _id: target.internal_id, retry_on_conflict: 5 } }, { script: { source: SET_PENDING_CLUSTER_SCRIPT, lang: 'painless', params: { pending: moved } } }]
      : [{ index: { _index: INDEX_INTERNAL_OBJECTS, _id: targetId } }, buildGraphClusterSkeleton(targetId, now, moved)];
    // its document receives the staged fields of the cluster taking its id
    if (receivingIds.has(cluster.internal_id)) return write;
    const release = cluster.last_run_id
      ? [{ update: { _index: cluster._index, _id: cluster.internal_id, retry_on_conflict: 5 } }, { script: { source: 'ctx._source.remove(\'pending_cluster\')', lang: 'painless' } }]
      : [{ delete: { _index: cluster._index, _id: cluster.internal_id } }];
    return [...write, ...release];
  });
  if (body.length > 0) {
    await assertRunLease();
    await elBulk(context, { refresh: true, timeout: '5m', body });
  }
  return renames.size;
};

const publishRunClusters = async (runId: string, assertRunLease: () => Promise<void>) => {
  await assertRunLease();
  await updateRunClusters(CLUSTER_PUBLISH_SCRIPT, { term: { 'pending_cluster.run_id': runId } }, 'Graph analytics clusters publication fail');
  await assertRunLease();
  await updateRunClusters(CLUSTER_DROP_PENDING_SCRIPT, {
    bool: {
      must: [{ exists: { field: 'pending_cluster' } }],
      must_not: [{ term: { 'pending_cluster.run_id': runId } }],
    },
  }, 'Graph analytics pending clusters cleanup fail');
};

/**
 * Finalize a clustering run: its staged entity metrics become the live ones, clusters not refreshed by the run are
 * deleted (whatever their source, only one source is active at a time) and entity assignments written by older runs
 * are detached. `publishedAt` is the joining date recorded on the entities that changed cluster. `assertRunLease` is
 * awaited before every write (each update by query and each bulk chunk) and throws when the run no longer holds the
 * write lease, so a run that lost it stops before its next write.
 * Cluster documents and member assignments live in different indices, so the switch is ordered, not atomic: a member
 * always points to a published cluster document, but while the switch runs (or after an interruption) a cluster may
 * show the new metadata with part of its previous memberships, and a stale cluster may remain until its removal.
 * Every step is keyed on the run id, so the next completed run converges the whole state.
 */
export const finalizeClusteringRun = async (
  context: AuthContext,
  user: AuthUser,
  runId: string,
  assertRunLease: () => Promise<void>,
): Promise<{ removed: string[]; publishedAt: string }> => {
  const publishedAt = new Date().toISOString();
  await assertRunLease();
  await reconcileRunClusterIdentities(context, runId, assertRunLease);
  // clusters are published before their members point to them, so a cluster never shows another run's metadata
  await publishRunClusters(runId, assertRunLease);
  await assertRunLease();
  await promoteRunMetrics(runId, publishedAt);
  await assertRunLease();
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
    await assertRunLease();
    await elBulk(context, { refresh: true, body });
  }
  await assertRunLease();
  await clearRunMetricsNotFromRun(runId);
  return { removed: stale.map((s) => s.internal_id), publishedAt };
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
