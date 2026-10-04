import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, GRAPH_ANALYTICS_MANAGER_USER } from '../utils/access';
import type { DataEvent, MergeEvent, SseEvent } from '../types/event';
import type { AuthContext, AuthUser } from '../types/user';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../database/utils';
import { fetchStreamEventsRangeFromEventId, fetchStreamInfo } from '../database/stream/stream-handler';
import {
  redisGetManagerEventState,
  redisGraphAnalyticsGetState,
  redisGraphAnalyticsMarkDirty,
  redisGraphAnalyticsPopReady,
  redisGraphAnalyticsSetState,
  redisSetManagerEventState,
} from '../database/redis';
import { deleteSimilarityRowsForEntities } from '../modules/graphAnalytics/graphAnalytics-store';
import {
  getGraphAnalyticsComputeConfig,
  type GraphAnalyticsComputeConfig,
  isFullPassInProgress,
  processDirtyEntities,
  runFullPassStep,
  runInfrastructureClustering,
  shouldStartFullPass,
  startFullPass,
} from '../modules/graphAnalytics/graphAnalytics-compute';
import { GRAPH_PROFILED_ENTITY_TYPES } from '../modules/graphAnalytics/graphAnalytics-features';
import { GRAPH_ANALYTICS_MANAGER_NAME, GRAPH_STATE_LAST_INCREMENTAL_RUN } from '../modules/graphAnalytics/graphAnalytics-state';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';

const GRAPH_ANALYTICS_MANAGER_ID = 'GRAPH_ANALYTICS_MANAGER';
const GRAPH_ANALYTICS_MANAGER_LABEL = 'Graph analytics manager';
const GRAPH_ANALYTICS_MANAGER_CONTEXT = 'graph_analytics_manager';

const GRAPH_ANALYTICS_MANAGER_ENABLED = booleanConf('graph_analytics_manager:enabled', true);
const GRAPH_ANALYTICS_MANAGER_LOCK_KEY = conf.get('graph_analytics_manager:lock_key');
const GRAPH_ANALYTICS_MANAGER_INTERVAL = conf.get('graph_analytics_manager:interval') ?? 30000;
const GRAPH_ANALYTICS_STREAM_BATCH_SIZE = conf.get('graph_analytics_manager:stream_batch_size') ?? 5000;
const GRAPH_ANALYTICS_MAX_ENTITIES_PER_TICK = conf.get('graph_analytics_manager:max_entities_per_tick') ?? 200;
// Each step of the nightly sweep is time-boxed under the manager interval
const FULL_PASS_STEP_BUDGET_MS = Math.max(5000, Math.floor(GRAPH_ANALYTICS_MANAGER_INTERVAL * 0.6));

export interface GraphAnalyticsEventImpact {
  dirty: string[];
  removed: string[];
}

/** Entities whose graph metrics or similarity may change because of a stream event. */
export const extractGraphAnalyticsImpact = (event: SseEvent<DataEvent>): GraphAnalyticsEventImpact => {
  const dirty: string[] = [];
  const removed: string[] = [];
  const { data: eventData } = event;
  const stix = eventData.data as any;
  const extension = stix?.extensions?.[STIX_EXT_OCTI];
  if (!extension) return { dirty, removed };
  if (stix.type === STIX_TYPE_RELATION) {
    if (extension.source_ref) dirty.push(extension.source_ref);
    if (extension.target_ref) dirty.push(extension.target_ref);
    return { dirty, removed };
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    if (extension.sighting_of_ref) dirty.push(extension.sighting_of_ref);
    (extension.where_sighted_refs ?? []).forEach((ref: string) => dirty.push(ref));
    return { dirty, removed };
  }
  const entityId: string | undefined = extension.id;
  const entityType: string | undefined = extension.type;
  if (!entityId || !entityType) return { dirty, removed };
  switch (eventData.type) {
    case EVENT_TYPE_CREATE:
      if (GRAPH_PROFILED_ENTITY_TYPES.includes(entityType)) dirty.push(entityId);
      break;
    case EVENT_TYPE_DELETE:
      removed.push(entityId);
      break;
    case EVENT_TYPE_MERGE: {
      dirty.push(entityId);
      const sources = (eventData as unknown as MergeEvent).context?.sources ?? [];
      sources.forEach((source: any) => {
        const sourceId = source?.extensions?.[STIX_EXT_OCTI]?.id;
        if (sourceId) removed.push(sourceId);
      });
      break;
    }
    case EVENT_TYPE_UPDATE:
      // containment changes the features of reports
      if (entityType === ENTITY_TYPE_CONTAINER_REPORT) dirty.push(entityId);
      break;
    default:
      break;
  }
  return { dirty, removed };
};

const processStreamEvents = async (events: Array<SseEvent<DataEvent>>) => {
  const dirty = new Set<string>();
  const removed = new Set<string>();
  events.forEach((event) => {
    const impact = extractGraphAnalyticsImpact(event);
    impact.dirty.forEach((id) => dirty.add(id));
    impact.removed.forEach((id) => removed.add(id));
  });
  removed.forEach((id) => dirty.delete(id));
  if (removed.size > 0) {
    await deleteSimilarityRowsForEntities(Array.from(removed));
  }
  await redisGraphAnalyticsMarkDirty(Array.from(dirty));
};

const STREAM_MAX_BATCHES_PER_TICK = 20;

export const resolveStreamStart = async (): Promise<string> => {
  const lastEventId = await redisGetManagerEventState(GRAPH_ANALYTICS_MANAGER_NAME);
  if (lastEventId) return lastEventId;
  // first start: begin at the live position, the initial full pass covers the existing knowledge
  let start = '0-0';
  try {
    const streamInfo = await fetchStreamInfo();
    start = streamInfo.lastEventId;
  } catch {
    // no stream yet: every event is new
  }
  // saved at once: otherwise a tick receiving no event starts the next one at the live position, skipping what came in between
  await redisSetManagerEventState(GRAPH_ANALYTICS_MANAGER_NAME, start);
  return start;
};

const consumeStream = async () => {
  let cursor = await resolveStreamStart();
  for (let batch = 0; batch < STREAM_MAX_BATCHES_PER_TICK; batch += 1) {
    let received = 0;
    const pending: Array<Promise<void>> = [];
    const result = await fetchStreamEventsRangeFromEventId<DataEvent>(
      cursor,
      (events) => {
        received += events.length;
        pending.push(processStreamEvents(events));
      },
      { streamBatchSize: GRAPH_ANALYTICS_STREAM_BATCH_SIZE },
    );
    await Promise.all(pending);
    const advanced = !!result.lastEventId && result.lastEventId !== cursor;
    if (advanced) {
      cursor = result.lastEventId;
      await redisSetManagerEventState(GRAPH_ANALYTICS_MANAGER_NAME, cursor);
    }
    if (!advanced || received < GRAPH_ANALYTICS_STREAM_BATCH_SIZE) break;
  }
};

/**
 * Recompute the entities whose last change is older than the debounce delay (and the explicit requests).
 * The batch is popped before the computation: when it fails, it is queued again and retried after the debounce delay.
 * Entities whose similarity alone failed are queued again the same way.
 */
export const processReadyEntities = async (context: AuthContext, user: AuthUser, config: GraphAnalyticsComputeConfig) => {
  const ready = await redisGraphAnalyticsPopReady(Date.now() - config.debounceMs, GRAPH_ANALYTICS_MAX_ENTITIES_PER_TICK);
  if (ready.length === 0) return { processed: 0, removed: 0, failed: [] };
  try {
    const result = await processDirtyEntities(context, user, ready, config);
    if (result.failed.length > 0) {
      await redisGraphAnalyticsMarkDirty(result.failed);
    }
    await redisGraphAnalyticsSetState({ [GRAPH_STATE_LAST_INCREMENTAL_RUN]: new Date().toISOString() });
    return result;
  } catch (err) {
    await redisGraphAnalyticsMarkDirty(ready);
    throw err;
  }
};

/**
 * Nightly sweep (degree metrics refresh and similarity backfill), then clustering.
 * Clustering selects entities by their degree metrics, so it only runs once the sweep reached the end of the entities:
 * a pass stopped at its entity cap would cluster a partial view of the platform.
 */
export const runFullPassTick = async (context: AuthContext, user: AuthUser, config: GraphAnalyticsComputeConfig) => {
  const state = await redisGraphAnalyticsGetState();
  if (shouldStartFullPass(state, config)) {
    await startFullPass();
    logApp.info('[OPENCTI-MODULE] Graph analytics full pass started');
  }
  if (!isFullPassInProgress(await redisGraphAnalyticsGetState())) {
    return null;
  }
  const { outcome, processed } = await runFullPassStep(context, user, config, FULL_PASS_STEP_BUDGET_MS);
  if (outcome === 'completed') {
    logApp.info('[OPENCTI-MODULE] Graph analytics full pass completed', { processed });
    const clustering = await runInfrastructureClustering(context, user, config);
    logApp.info('[OPENCTI-MODULE] Graph analytics infrastructure clustering', clustering);
  }
  return outcome;
};

export const graphAnalyticsManagerHandler = async () => {
  const context: AuthContext = executionContext(GRAPH_ANALYTICS_MANAGER_CONTEXT, GRAPH_ANALYTICS_MANAGER_USER);
  const user = GRAPH_ANALYTICS_MANAGER_USER;
  const config = getGraphAnalyticsComputeConfig();
  // 1. Mark entities touched since the last tick
  await consumeStream();
  // 2. Recompute entities whose last change is older than the debounce delay
  const { processed, removed } = await processReadyEntities(context, user, config);
  if (processed > 0 || removed > 0) {
    logApp.debug('[OPENCTI-MODULE] Graph analytics incremental recompute', { processed, removed });
  }
  // 3. Nightly sweep, then clustering
  await runFullPassTick(context, user, config);
};

const GRAPH_ANALYTICS_MANAGER_DEFINITION: ManagerDefinition = {
  id: GRAPH_ANALYTICS_MANAGER_ID,
  label: GRAPH_ANALYTICS_MANAGER_LABEL,
  executionContext: GRAPH_ANALYTICS_MANAGER_CONTEXT,
  enabledByConfig: GRAPH_ANALYTICS_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig && !!GRAPH_ANALYTICS_MANAGER_LOCK_KEY;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig && !!GRAPH_ANALYTICS_MANAGER_LOCK_KEY;
  },
  cronSchedulerHandler: {
    handler: graphAnalyticsManagerHandler,
    interval: GRAPH_ANALYTICS_MANAGER_INTERVAL,
    lockKey: GRAPH_ANALYTICS_MANAGER_LOCK_KEY,
  },
};

registerManager(GRAPH_ANALYTICS_MANAGER_DEFINITION);
