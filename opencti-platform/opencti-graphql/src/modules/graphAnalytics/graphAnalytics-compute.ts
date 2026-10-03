import { v4 as uuidv4 } from 'uuid';
import conf, { logApp } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreBase } from '../../types/store';
import { elList, elPaginate } from '../../database/engine';
import { ABSTRACT_STIX_CORE_OBJECT } from '../../schema/general';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { doYield } from '../../utils/eventloop-utils';
import { redisGraphAnalyticsDeleteState, redisGraphAnalyticsGetState, redisGraphAnalyticsMarkDirty, redisGraphAnalyticsSetState } from '../../database/redis';
import {
  candidateQueriesForKind,
  classifyInfrastructureNeighbor,
  classifyThreatNeighbor,
  getGraphProfileSpec,
  GRAPH_PROFILED_ENTITY_TYPES,
  type GraphProfileSpec,
  INFRASTRUCTURE_ENTITY_TYPES,
  listAnalyticsRelations,
  loadFeatureProfiles,
} from './graphAnalytics-features';
import { rankSimilarProfiles, weightedSharedCount } from './graphAnalytics-scoring';
import {
  computeDegreeMetrics,
  countRelationshipsPerElement,
  deleteSimilarityRowsForEntities,
  finalizeClusteringRun,
  GRAPH_METRICS_ENTITY_INDICES,
  type GraphMetricsUpdate,
  loadMetricsCarriers,
  replaceSimilarityRows,
  upsertGraphClusters,
  writeGraphMetrics,
} from './graphAnalytics-store';
import { buildGraphClusterId, computeFeatureClusters, type ClusteringMember } from './graphAnalytics-clustering';
import { GRAPH_METRICS_ATTRIBUTE, type GraphClusterKind, type GraphFeatureFamily, type GraphFeatureProfile, type GraphMetrics } from './graphAnalytics-types';
import {
  GRAPH_STATE_CLUSTERING_LAST_RUN,
  GRAPH_STATE_FULL_PASS_COMPLETED_AT,
  GRAPH_STATE_FULL_PASS_CURSOR,
  GRAPH_STATE_FULL_PASS_PROCESSED,
  GRAPH_STATE_FULL_PASS_STARTED_AT,
  isAnalyticsProcessActive,
  parseStateDate,
} from './graphAnalytics-state';

export interface GraphAnalyticsComputeConfig {
  topN: number;
  minScore: number;
  maxCandidates: number;
  featureMaxFanout: number;
  featureMaxPerFamily: number;
  maxRelationships: number;
  debounceMs: number;
  fullPassHour: number;
  fullPassBatchSize: number;
  fullPassMaxEntities: number;
  clusteringEnabled: boolean;
  clusteringMaxEntities: number;
  clusteringFeatureMaxFanout: number;
  clusteringMinSize: number;
}

export const getGraphAnalyticsComputeConfig = (): GraphAnalyticsComputeConfig => ({
  topN: conf.get('graph_analytics_manager:similarity_top_n') ?? 20,
  minScore: conf.get('graph_analytics_manager:similarity_min_score') ?? 0.05,
  maxCandidates: conf.get('graph_analytics_manager:similarity_max_candidates') ?? 200,
  featureMaxFanout: conf.get('graph_analytics_manager:feature_max_fanout') ?? 500,
  featureMaxPerFamily: conf.get('graph_analytics_manager:feature_max_per_family') ?? 500,
  maxRelationships: 50000,
  debounceMs: conf.get('graph_analytics_manager:debounce_ms') ?? 60000,
  fullPassHour: conf.get('graph_analytics_manager:full_pass_hour') ?? 2,
  fullPassBatchSize: conf.get('graph_analytics_manager:full_pass_batch_size') ?? 1000,
  fullPassMaxEntities: conf.get('graph_analytics_manager:full_pass_max_entities') ?? 2000000,
  clusteringEnabled: conf.get('graph_analytics_manager:clustering_enabled') ?? true,
  clusteringMaxEntities: conf.get('graph_analytics_manager:clustering_max_entities') ?? 100000,
  clusteringFeatureMaxFanout: conf.get('graph_analytics_manager:clustering_feature_max_fanout') ?? 50,
  clusteringMinSize: conf.get('graph_analytics_manager:clustering_min_size') ?? 3,
});

const PROFILE_BATCH_SIZE = 25;
const STALE_SIMILARITY_DAYS = 7;
// Families linking infrastructure elements into a cluster (shared certificate, ASN, registrar, nameserver, hosting, report).
export const INFRASTRUCTURE_CLUSTER_FAMILIES: GraphFeatureFamily[] = ['certificates', 'asn', 'registrar', 'nameservers', 'hosting', 'reports'];

const featureOptions = (config: GraphAnalyticsComputeConfig) => ({
  maxPerFamily: config.featureMaxPerFamily,
  maxRelationships: config.maxRelationships,
});

export const loadFeatureProfilesBatched = async (
  context: AuthContext,
  user: AuthUser,
  entities: Array<{ id: string; entity_type: string }>,
  config: GraphAnalyticsComputeConfig,
  checkEndpointsAccess = false,
): Promise<GraphFeatureProfile[]> => {
  const profiles: GraphFeatureProfile[] = [];
  for (let i = 0; i < entities.length; i += PROFILE_BATCH_SIZE) {
    const batch = entities.slice(i, i + PROFILE_BATCH_SIZE);
    const loaded = await loadFeatureProfiles(context, user, batch, { ...featureOptions(config), checkEndpointsAccess });
    profiles.push(...loaded.values());
    await doYield();
  }
  return profiles;
};

/**
 * Entities of the same comparison group sharing at least one discriminative feature with the profile,
 * pre-ranked on the weighted amount of shared features.
 */
export const findSimilarityCandidates = async (
  context: AuthContext,
  user: AuthUser,
  profile: GraphFeatureProfile,
  spec: GraphProfileSpec,
  config: GraphAnalyticsComputeConfig,
): Promise<Array<{ id: string; entity_type: string }>> => {
  const candidates = new Map<string, { type: string; byFamily: Map<GraphFeatureFamily, Set<string>> }>();
  const queries = candidateQueriesForKind(spec.kind);
  for (let q = 0; q < queries.length; q += 1) {
    const query = queries[q];
    const featureIds = profile.features[query.family] ?? [];
    if (featureIds.length === 0) continue;
    const fanout = await countRelationshipsPerElement(context, user, featureIds, query.relationshipTypes);
    const usable = featureIds.filter((id) => (fanout.get(id) ?? 0) <= config.featureMaxFanout);
    if (usable.length === 0) continue;
    const usableSet = new Set(usable);
    let args;
    if (query.featureSide === 'to') args = { toId: usable, fromTypes: spec.entityTypes };
    else if (query.featureSide === 'from') args = { fromId: usable, toTypes: spec.entityTypes };
    else args = { fromOrToId: usable };
    const relations = await listAnalyticsRelations(context, user, query.relationshipTypes, args, config.maxRelationships);
    relations.forEach((relation) => {
      let candidateId: string;
      let candidateType: string;
      let featureId: string;
      let featureType: string;
      if (query.featureSide === 'to') {
        [candidateId, candidateType, featureId, featureType] = [relation.fromId, relation.fromType, relation.toId, relation.toType];
      } else if (query.featureSide === 'from') {
        [candidateId, candidateType, featureId, featureType] = [relation.toId, relation.toType, relation.fromId, relation.fromType];
      } else if (usableSet.has(relation.fromId)) {
        [candidateId, candidateType, featureId, featureType] = [relation.toId, relation.toType, relation.fromId, relation.fromType];
      } else {
        [candidateId, candidateType, featureId, featureType] = [relation.fromId, relation.fromType, relation.toId, relation.toType];
      }
      if (candidateId === profile.id || !spec.entityTypes.includes(candidateType) || !usableSet.has(featureId)) return;
      // the shared element must play the same role for the candidate
      if (spec.kind === 'threat' && classifyThreatNeighbor(relation.relationship_type, 'out', featureType) !== query.family) return;
      if (spec.kind === 'infrastructure' && query.family !== 'reports' && classifyInfrastructureNeighbor(candidateType, featureType) !== query.family) return;
      const entry = candidates.get(candidateId) ?? { type: candidateType, byFamily: new Map() };
      const shared = entry.byFamily.get(query.family) ?? new Set<string>();
      shared.add(featureId);
      entry.byFamily.set(query.family, shared);
      candidates.set(candidateId, entry);
    });
    await doYield();
  }
  return Array.from(candidates.entries())
    .map(([id, entry]) => {
      const counts: Partial<Record<GraphFeatureFamily, number>> = {};
      entry.byFamily.forEach((set, family) => {
        counts[family] = set.size;
      });
      return { id, entity_type: entry.type, rank: weightedSharedCount(counts) };
    })
    .sort((a, b) => (b.rank - a.rank) || a.id.localeCompare(b.id))
    .slice(0, config.maxCandidates)
    .map(({ id, entity_type }) => ({ id, entity_type }));
};

/** Recompute and store the top-N similar entities of an entity. */
export const computeEntitySimilarity = async (
  context: AuthContext,
  user: AuthUser,
  entity: { id: string; entity_type: string },
  config: GraphAnalyticsComputeConfig,
) => {
  const spec = getGraphProfileSpec(entity.entity_type);
  if (!spec) return { kept: 0, written: 0 };
  const profiles = await loadFeatureProfiles(context, user, [entity], featureOptions(config));
  const profile = profiles.get(entity.id);
  if (!profile) return { kept: 0, written: 0 };
  const candidates = await findSimilarityCandidates(context, user, profile, spec, config);
  const candidateProfiles = await loadFeatureProfilesBatched(context, user, candidates, config);
  const scored = rankSimilarProfiles(profile, candidateProfiles, Number.MAX_SAFE_INTEGER, config.minScore);
  return replaceSimilarityRows(context, user, entity, scored, config.topN);
};

const degreeChanged = (current: GraphMetrics | undefined | null, degree: number) => (current?.degree ?? 0) !== degree;

const buildDegreeUpdates = (
  carriers: BasicStoreBase[],
  degrees: Map<string, { degree: number; degree_by_type: { relationship_type: string; count: number }[] }>,
  computedAt: string,
  force: boolean,
): { updates: GraphMetricsUpdate[]; changed: BasicStoreBase[] } => {
  const updates: GraphMetricsUpdate[] = [];
  const changed: BasicStoreBase[] = [];
  carriers.forEach((carrier) => {
    const current = (carrier as unknown as Record<string, GraphMetrics | undefined>)[GRAPH_METRICS_ATTRIBUTE];
    const degree = degrees.get(carrier.internal_id) ?? { degree: 0, degree_by_type: [] };
    const hasChanged = degreeChanged(current, degree.degree);
    if (hasChanged) changed.push(carrier);
    // isolated entities never computed are left untouched to avoid useless writes
    if (!current && degree.degree === 0) return;
    if (force || hasChanged || !current?.computed_at) {
      updates.push({
        id: carrier.internal_id,
        index: carrier._index,
        metrics: { degree: degree.degree, degree_by_type: degree.degree_by_type, computed_at: computedAt },
      });
    }
  });
  return { updates, changed };
};

/** Debounced recompute of entities touched by stream events: degree metrics, then similarity. */
export const processDirtyEntities = async (
  context: AuthContext,
  user: AuthUser,
  ids: string[],
  config: GraphAnalyticsComputeConfig,
): Promise<{ processed: number; removed: number; failed: string[] }> => {
  if (ids.length === 0) return { processed: 0, removed: 0, failed: [] };
  const uniqueIds = Array.from(new Set(ids));
  const carriers = await loadMetricsCarriers(context, user, uniqueIds);
  const foundIds = new Set(carriers.map((c) => c.internal_id));
  const removedIds = uniqueIds.filter((id) => !foundIds.has(id));
  if (removedIds.length > 0) {
    await deleteSimilarityRowsForEntities(removedIds);
  }
  const degrees = await computeDegreeMetrics(context, user, carriers.map((c) => c.internal_id));
  const { updates } = buildDegreeUpdates(carriers, degrees, new Date().toISOString(), true);
  await writeGraphMetrics(context, updates);
  const failed: string[] = [];
  for (let i = 0; i < carriers.length; i += 1) {
    const carrier = carriers[i];
    if (GRAPH_PROFILED_ENTITY_TYPES.includes(carrier.entity_type)) {
      try {
        await computeEntitySimilarity(context, user, { id: carrier.internal_id, entity_type: carrier.entity_type }, config);
      } catch (err) {
        logApp.error('[OPENCTI-MODULE] Graph analytics similarity computation fail', { cause: err, id: carrier.internal_id });
        failed.push(carrier.internal_id);
      }
    }
    await doYield();
  }
  return { processed: carriers.length, removed: removedIds.length, failed };
};

// region full pass
export const isFullPassInProgress = (state: Record<string, string>) => {
  const started = parseStateDate(state[GRAPH_STATE_FULL_PASS_STARTED_AT]);
  const completed = parseStateDate(state[GRAPH_STATE_FULL_PASS_COMPLETED_AT]);
  return !!started && (!completed || completed.getTime() < started.getTime());
};

/** A full pass starts immediately on a platform never analyzed (backfill), then once a day at the configured hour. */
export const shouldStartFullPass = (state: Record<string, string>, config: GraphAnalyticsComputeConfig, now = new Date()) => {
  if (isFullPassInProgress(state)) return false;
  const completed = parseStateDate(state[GRAPH_STATE_FULL_PASS_COMPLETED_AT]);
  if (!completed) return true;
  const elapsed = now.getTime() - completed.getTime();
  return elapsed >= 20 * 3600 * 1000 && now.getUTCHours() === config.fullPassHour;
};

/** A pass starts where the previous capped pass stopped (the cursor is only cleared when a pass reaches the end). */
export const startFullPass = async () => {
  await redisGraphAnalyticsSetState({ [GRAPH_STATE_FULL_PASS_STARTED_AT]: new Date().toISOString(), [GRAPH_STATE_FULL_PASS_PROCESSED]: '0' });
};

/**
 * One time-boxed step of the nightly sweep over every Stix Core Object: refresh degree metrics where they changed,
 * and queue the profiled entities whose similarity may be outdated. The cursor is persisted, so a sweep survives
 * restarts and never holds the manager lock for long.
 */
export const runFullPassStep = async (
  context: AuthContext,
  user: AuthUser,
  config: GraphAnalyticsComputeConfig,
  budgetMs: number,
): Promise<{ processed: number; completed: boolean }> => {
  const startTime = Date.now();
  const state = await redisGraphAnalyticsGetState();
  let cursor: string | undefined = state[GRAPH_STATE_FULL_PASS_CURSOR] || undefined;
  let processedTotal = Number(state[GRAPH_STATE_FULL_PASS_PROCESSED] ?? '0') || 0;
  let processed = 0;
  let completed = false;
  const staleBefore = Date.now() - STALE_SIMILARITY_DAYS * 24 * 3600 * 1000;
  while (Date.now() - startTime < budgetMs) {
    const page = await elPaginate<BasicStoreBase>(context, user, GRAPH_METRICS_ENTITY_INDICES, {
      types: [ABSTRACT_STIX_CORE_OBJECT],
      first: config.fullPassBatchSize,
      after: cursor,
      baseData: true,
      baseFields: [GRAPH_METRICS_ATTRIBUTE],
      withResultMeta: true,
      connectionFormat: false,
    }) as unknown as { elements: BasicStoreBase[]; endCursor: string | null };
    const carriers = page.elements;
    if (carriers.length > 0) {
      const degrees = await computeDegreeMetrics(context, user, carriers.map((c) => c.internal_id));
      const { updates, changed } = buildDegreeUpdates(carriers, degrees, new Date().toISOString(), false);
      await writeGraphMetrics(context, updates);
      const changedIds = new Set(changed.map((c) => c.internal_id));
      const toQueue = carriers.filter((carrier) => {
        if (!GRAPH_PROFILED_ENTITY_TYPES.includes(carrier.entity_type)) return false;
        if ((degrees.get(carrier.internal_id)?.degree ?? 0) === 0) return false;
        const current = (carrier as unknown as Record<string, GraphMetrics | undefined>)[GRAPH_METRICS_ATTRIBUTE];
        const computedAt = current?.computed_at ? new Date(current.computed_at).getTime() : 0;
        return changedIds.has(carrier.internal_id) || computedAt < staleBefore;
      }).map((carrier) => carrier.internal_id);
      // ready immediately, but after entities changed by recent events
      await redisGraphAnalyticsMarkDirty(toQueue, Date.now() - config.debounceMs - 1);
      processed += carriers.length;
      processedTotal += carriers.length;
    }
    if (!page.endCursor || carriers.length < config.fullPassBatchSize) {
      cursor = undefined;
      completed = true;
      break;
    }
    cursor = page.endCursor;
    if (processedTotal >= config.fullPassMaxEntities) {
      // the next pass resumes from here, so entities beyond the cap are rotated in instead of never being swept
      logApp.info('[OPENCTI-MODULE] Graph analytics full pass capped, the next pass resumes from its cursor', { max: config.fullPassMaxEntities });
      completed = true;
      break;
    }
    await doYield();
  }
  if (completed) {
    if (cursor) {
      await redisGraphAnalyticsSetState({ [GRAPH_STATE_FULL_PASS_CURSOR]: cursor });
    } else {
      await redisGraphAnalyticsDeleteState([GRAPH_STATE_FULL_PASS_CURSOR]);
    }
    await redisGraphAnalyticsSetState({
      [GRAPH_STATE_FULL_PASS_COMPLETED_AT]: new Date().toISOString(),
      [GRAPH_STATE_FULL_PASS_PROCESSED]: String(processedTotal),
    });
  } else {
    await redisGraphAnalyticsSetState({
      [GRAPH_STATE_FULL_PASS_CURSOR]: cursor ?? '',
      [GRAPH_STATE_FULL_PASS_PROCESSED]: String(processedTotal),
    });
  }
  return { processed, completed };
};
// endregion

// region clustering
export interface ClusterAssignment {
  entity_id: string;
  cluster_id: string;
  cluster_kind: GraphClusterKind;
  cluster_size: number;
}

/** Write cluster assignments (and optional centrality) of a run on the member entities. */
export const writeRunMetrics = async (
  context: AuthContext,
  user: AuthUser,
  runId: string,
  entries: Array<{ entity_id: string; cluster_id?: string | null; cluster_kind?: GraphClusterKind | null; cluster_size?: number | null; betweenness_approx?: number | null }>,
): Promise<{ updated: number; skipped: number }> => {
  const carriers = await loadMetricsCarriers(context, user, entries.map((e) => e.entity_id));
  const byId = new Map(carriers.map((c) => [c.internal_id, c]));
  const updates: GraphMetricsUpdate[] = [];
  entries.forEach((entry) => {
    const carrier = byId.get(entry.entity_id);
    if (!carrier) return;
    const metrics: GraphMetricsUpdate['metrics'] = { run_id: runId };
    if (entry.cluster_id !== undefined) {
      metrics.cluster_id = entry.cluster_id;
      metrics.cluster_kind = entry.cluster_id ? entry.cluster_kind ?? null : null;
      metrics.cluster_size = entry.cluster_id ? entry.cluster_size ?? null : null;
    }
    if (entry.betweenness_approx !== undefined) {
      metrics.betweenness_approx = entry.betweenness_approx;
    }
    updates.push({ id: carrier.internal_id, index: carrier._index, metrics });
  });
  await writeGraphMetrics(context, updates);
  return { updated: updates.length, skipped: entries.length - updates.length };
};

/**
 * In-platform clustering of infrastructure (domains, addresses, URLs, certificates, infrastructures) on shared
 * discriminative features. Skipped while the opencti-analytics process is active: it then owns clusters.
 */
export const runInfrastructureClustering = async (
  context: AuthContext,
  user: AuthUser,
  config: GraphAnalyticsComputeConfig,
): Promise<{ clusters: number; members: number; skipped: boolean }> => {
  const state = await redisGraphAnalyticsGetState();
  if (!config.clusteringEnabled || isAnalyticsProcessActive(state)) {
    return { clusters: 0, members: 0, skipped: true };
  }
  const runId = uuidv4();
  const population = await elList<BasicStoreBase>(context, user, GRAPH_METRICS_ENTITY_INDICES, {
    types: INFRASTRUCTURE_ENTITY_TYPES,
    first: 5000,
    maxSize: config.clusteringMaxEntities + 1,
    baseData: true,
    noFiltersChecking: true,
    filters: {
      mode: FilterMode.And,
      filters: [{ key: [`${GRAPH_METRICS_ATTRIBUTE}.degree`], values: ['1'], operator: FilterOperator.Gte }],
      filterGroups: [],
    },
  });
  // Finalizing replaces every cluster of older runs: a partial population would wrongly dissolve the others
  if (population.length > config.clusteringMaxEntities) {
    logApp.warn('[OPENCTI-MODULE] Graph analytics infrastructure clustering skipped, too many entities: raise clustering_max_entities or deploy opencti-analytics', {
      max: config.clusteringMaxEntities,
    });
    return { clusters: 0, members: 0, skipped: true };
  }
  const profiles = await loadFeatureProfilesBatched(context, user, population.map((p) => ({ id: p.internal_id, entity_type: p.entity_type })), config);
  const members: ClusteringMember[] = profiles.map((profile) => ({ id: profile.id, type: profile.entity_type, features: profile.features }));
  const clusters = computeFeatureClusters(members, {
    families: INFRASTRUCTURE_CLUSTER_FAMILIES,
    maxFeatureFanout: config.clusteringFeatureMaxFanout,
    minClusterSize: config.clusteringMinSize,
  });
  const kind: GraphClusterKind = 'infrastructure';
  const writes = clusters.map((cluster) => ({
    cluster_id: buildGraphClusterId(kind, cluster.anchor),
    cluster_kind: kind,
    members_count: cluster.members.length,
    representative_ids: cluster.representative_ids,
    features: cluster.features,
    members: cluster.members,
  }));
  const assignments = writes.flatMap((write) => write.members.map((memberId) => ({
    entity_id: memberId,
    cluster_id: write.cluster_id,
    cluster_kind: kind,
    cluster_size: write.members_count,
  })));
  for (let i = 0; i < assignments.length; i += 1000) {
    await writeRunMetrics(context, user, runId, assignments.slice(i, i + 1000));
  }
  await upsertGraphClusters(context, user, writes, 'platform', runId);
  await finalizeClusteringRun(context, user, runId);
  await redisGraphAnalyticsSetState({ [GRAPH_STATE_CLUSTERING_LAST_RUN]: new Date().toISOString() });
  return { clusters: writes.length, members: assignments.length, skipped: false };
};
// endregion
