import { Promise as BluePromise } from 'bluebird';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent } from '../types/event';
import type { BasicStoreEntity, BasicStoreRelation } from '../types/store';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { fetchStreamEventsRangeFromEventId, fetchStreamInfo } from '../database/stream/stream-handler';
import { redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import { fullEntitiesList, fullRelationsList, internalFindByIds } from '../database/middleware-loader';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, buildRefRelationKey, STIX_TYPE_RELATION, STIX_TYPE_SIGHTING } from '../schema/general';
import { RELATION_OBJECT } from '../schema/stixRefRelationship';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INCIDENT } from '../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_TASK } from '../modules/task/task-types';
import { FilterMode } from '../generated/graphql';
import { ENTITY_TYPE_TIMELINE_EVENT, ENTITY_TYPE_TIMELINE_SETTINGS, isTimelineContainerType, TIMELINE_CONTAINER_TYPES } from '../modules/timeline/timeline-types';
import { regenerateContainerTimeline } from '../modules/timeline/timeline-engine';
import {
  claimDueTimelineRegenerations,
  clearTimelineRegenerationAttempts,
  enqueueTimelineRegeneration,
  getTimelineConsistencyLastRun,
  retryTimelineRegeneration,
  setTimelineConsistencyLastRun,
} from '../modules/timeline/timeline-queue';

const TIMELINE_MANAGER_ID = 'TIMELINE_MANAGER';
const TIMELINE_MANAGER_LABEL = 'Timeline manager';
const TIMELINE_MANAGER_CONTEXT = 'timeline_manager';
const TIMELINE_MANAGER_STATE = 'timeline_manager';

const TIMELINE_MANAGER_ENABLED = booleanConf('timeline_manager:enabled', true);
const TIMELINE_MANAGER_LOCK_KEY = conf.get('timeline_manager:lock_key') ?? 'timeline_manager_lock';
const TIMELINE_MANAGER_INTERVAL = conf.get('timeline_manager:interval') ?? 10000;
const TIMELINE_MANAGER_STREAM_BATCH_SIZE = conf.get('timeline_manager:stream_batch_size') ?? 1000;
// Upper bound of stream batches read per run, so that the queue keeps being served under heavy ingestion
const TIMELINE_MANAGER_MAX_STREAM_BATCHES = conf.get('timeline_manager:max_stream_batches_per_run') ?? 20;
const TIMELINE_MANAGER_REGENERATION_BATCH = conf.get('timeline_manager:regeneration_batch_size') ?? 20;
const TIMELINE_MANAGER_MAX_CONCURRENCY = conf.get('timeline_manager:max_concurrency') ?? 2;
// Containers impacted by a single stream batch through a shared element are bounded
const TIMELINE_MANAGER_MAX_IMPACTED = conf.get('timeline_manager:max_impacted_containers') ?? 1000;
// Nightly consistency pass (UTC hour)
const TIMELINE_MANAGER_CONSISTENCY_HOUR = conf.get('timeline_manager:consistency_hour') ?? 2;

const CONTAINERS_REFERENCING_TYPES = [ENTITY_TYPE_CONTAINER_TASK, ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_CONTAINER_REPORT];

interface ImpactCollector {
  containers: Set<string>;
  // elements whose containing cases are impacted
  contained: Set<string>;
  // entities whose related incidents are impacted
  related: Set<string>;
  // stix ids referenced by tasks, notes, opinions and reports
  references: Set<string>;
}

/** Collect, from one stream event, what can impact a timeline (pure, no database access). */
export const collectTimelineImpacts = (event: SseEvent<DataEvent>, collector: ImpactCollector) => {
  const stix = event.data?.data as any;
  const extension = stix?.extensions?.[STIX_EXT_OCTI];
  if (!stix || !extension) return;
  if (extension.is_inferred) return;
  const type: string = extension.type;
  const id: string = extension.id;
  if (type === ENTITY_TYPE_TIMELINE_EVENT || type === ENTITY_TYPE_TIMELINE_SETTINGS) return;
  if (isTimelineContainerType(type)) {
    collector.containers.add(id);
    return;
  }
  if (CONTAINERS_REFERENCING_TYPES.includes(type)) {
    (stix.object_refs ?? []).forEach((ref: string) => collector.references.add(ref));
  }
  if (stix.type === STIX_TYPE_RELATION) {
    if (isTimelineContainerType(extension.source_type)) collector.containers.add(extension.source_ref);
    if (isTimelineContainerType(extension.target_type)) collector.containers.add(extension.target_ref);
    collector.contained.add(id);
    // Deployments and timed relationships of contained elements impact the cases containing them
    if (extension.source_ref) collector.contained.add(extension.source_ref);
    return;
  }
  if (stix.type === STIX_TYPE_SIGHTING) {
    collector.contained.add(id);
    // Sightings of contained indicators by security platforms are detections of the case
    if (extension.sighting_of_ref) collector.contained.add(extension.sighting_of_ref);
    return;
  }
  // Soft-check sources: Case Autopilot runs point to their subject, hunt runs to their hunt
  if (typeof stix.subject_id === 'string') collector.references.add(stix.subject_id);
  if (typeof stix.hunt_id === 'string') collector.contained.add(stix.hunt_id);
  collector.contained.add(id);
  collector.related.add(id);
};

const resolveImpactedContainers = async (context: AuthContext, collector: ImpactCollector): Promise<string[]> => {
  const impacted = new Set(collector.containers);
  const contained = Array.from(collector.contained);
  if (contained.length > 0) {
    const containers = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, TIMELINE_CONTAINER_TYPES, {
      filters: { mode: FilterMode.And, filters: [{ key: [buildRefRelationKey(RELATION_OBJECT)], values: contained }], filterGroups: [] },
      noFiltersChecking: true,
      baseData: true,
      maxSize: TIMELINE_MANAGER_MAX_IMPACTED,
    } as any);
    containers.forEach((c) => impacted.add(c.internal_id));
  }
  const references = Array.from(collector.references);
  if (references.length > 0) {
    const referenced = await internalFindByIds(context, SYSTEM_USER, references, { type: TIMELINE_CONTAINER_TYPES, baseData: true });
    (referenced as unknown as BasicStoreEntity[]).forEach((c) => impacted.add(c.internal_id));
  }
  const related = Array.from(collector.related);
  if (related.length > 0) {
    const relatedArgs = { baseData: true, maxSize: TIMELINE_MANAGER_MAX_IMPACTED };
    const [fromIncidents, toIncidents] = await Promise.all([
      fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, { ...relatedArgs, toId: related, fromTypes: [ENTITY_TYPE_INCIDENT] } as any),
      fullRelationsList<BasicStoreRelation>(context, SYSTEM_USER, ABSTRACT_STIX_CORE_RELATIONSHIP, { ...relatedArgs, fromId: related, toTypes: [ENTITY_TYPE_INCIDENT] } as any),
    ]);
    fromIncidents.forEach((r) => impacted.add(r.fromId));
    toIncidents.forEach((r) => impacted.add(r.toId));
  }
  return Array.from(impacted).filter((id) => !!id);
};

export const timelineStreamEventsHandler = async (context: AuthContext, streamEvents: Array<SseEvent<DataEvent>>) => {
  if (streamEvents.length === 0) return;
  const collector: ImpactCollector = { containers: new Set(), contained: new Set(), related: new Set(), references: new Set() };
  streamEvents.forEach((event) => collectTimelineImpacts(event, collector));
  const impacted = await resolveImpactedContainers(context, collector);
  await enqueueTimelineRegeneration(impacted);
};

const resolveStreamStart = async (): Promise<string> => {
  const state = await redisGetManagerEventState(TIMELINE_MANAGER_STATE);
  if (state) return state;
  // First start: listen from now on, the existing containers are backfilled by migration and consistency pass
  try {
    const info = await fetchStreamInfo();
    return info.lastEventId ?? '0-0';
  } catch {
    return '0-0';
  }
};

const consumeStream = async (context: AuthContext) => {
  let lastEventId = await resolveStreamStart();
  for (let batch = 0; batch < TIMELINE_MANAGER_MAX_STREAM_BATCHES; batch += 1) {
    const result = await fetchStreamEventsRangeFromEventId<DataEvent>(
      lastEventId,
      (events) => timelineStreamEventsHandler(context, events),
      { streamBatchSize: TIMELINE_MANAGER_STREAM_BATCH_SIZE },
    );
    const moved = result.lastEventId !== lastEventId;
    lastEventId = result.lastEventId;
    await redisSetManagerEventState(TIMELINE_MANAGER_STATE, lastEventId);
    if (!moved) break;
  }
};

export const processDueTimelineRegenerations = async (context: AuthContext) => {
  const due = await claimDueTimelineRegenerations(TIMELINE_MANAGER_REGENERATION_BATCH);
  await BluePromise.map(due, async (containerId) => {
    try {
      const result = await regenerateContainerTimeline(context, containerId);
      await clearTimelineRegenerationAttempts(containerId);
      if (result) {
        logApp.debug('[TIMELINE] Container timeline regenerated', { ...result, anchors: undefined });
      }
    } catch (error) {
      const retried = await retryTimelineRegeneration(containerId).catch(() => false);
      logApp.error('[TIMELINE] Container timeline regeneration failure', { cause: error, containerId, retried });
    }
  }, { concurrency: TIMELINE_MANAGER_MAX_CONCURRENCY });
};

/** Once a day, every timeline container is scheduled for regeneration (spread by the queue batch size). */
export const isTimelineConsistencyPassDue = (lastRun: number | null, nowTime: number, hour: number): boolean => {
  const today = new Date(nowTime);
  const scheduled = Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate(), hour);
  if (nowTime < scheduled) return false;
  return lastRun === null || lastRun < scheduled;
};

const runConsistencyPass = async (context: AuthContext) => {
  const nowTime = Date.now();
  const lastRun = await getTimelineConsistencyLastRun();
  if (!isTimelineConsistencyPassDue(lastRun, nowTime, TIMELINE_MANAGER_CONSISTENCY_HOUR)) return;
  await setTimelineConsistencyLastRun(nowTime);
  let scheduled = 0;
  await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, TIMELINE_CONTAINER_TYPES, {
    baseData: true,
    callback: async (containers: BasicStoreEntity[]) => {
      await enqueueTimelineRegeneration(containers.map((c) => c.internal_id));
      scheduled += containers.length;
    },
  } as any);
  logApp.info('[TIMELINE] Consistency pass scheduled', { scheduled });
};

export const timelineManagerHandler = async () => {
  const context = executionContext(TIMELINE_MANAGER_CONTEXT);
  await consumeStream(context);
  await processDueTimelineRegenerations(context);
  await runConsistencyPass(context);
};

const TIMELINE_MANAGER_DEFINITION: ManagerDefinition = {
  id: TIMELINE_MANAGER_ID,
  label: TIMELINE_MANAGER_LABEL,
  executionContext: TIMELINE_MANAGER_CONTEXT,
  enabledByConfig: TIMELINE_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: timelineManagerHandler,
    interval: TIMELINE_MANAGER_INTERVAL,
    lockKey: TIMELINE_MANAGER_LOCK_KEY,
  },
};

registerManager(TIMELINE_MANAGER_DEFINITION);
