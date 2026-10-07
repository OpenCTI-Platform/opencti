import * as R from 'ramda';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { CURATION_MANAGER_USER, executionContext } from '../utils/access';
import type { AuthContext } from '../types/user';
import type { DataEvent, SseEvent, UpdateEvent } from '../types/event';
import { STIX_EXT_OCTI } from '../types/stix-2-1-extensions';
import { EVENT_TYPE_DELETE, EVENT_TYPE_UPDATE } from '../database/utils';
import {
  redisCurationCompleteRestrictionRefresh,
  redisCurationFailRestrictionRefresh,
  redisCurationGetQueuedRestrictionRefreshes,
  redisCurationQueueRestrictionRefresh,
  redisGetManagerEventState,
  redisSetManagerEventState,
} from '../database/redis';
import { completePendingMergeRecords, expireMergeRecords, refreshMergeRecordRestrictions } from '../modules/curation/curation-merge-record';
import { refreshProposalRestrictions, retireProposalsOfDeletedSubjects } from '../modules/curation/curation-proposals';

/**
 * Keeps what curation stores consistent, whether the curation detectors run or not: completes the merge records an
 * interrupted merge left pending, closes the ones past their retention window, keeps the restrictions of merge
 * records and open proposals in line with their subjects when a subject is reclassified, and removes the open
 * proposals about a deleted subject.
 */
const CURATION_RECORDS_MANAGER_ID = 'CURATION_RECORDS_MANAGER';
const CURATION_RECORDS_MANAGER_LABEL = 'Curation records manager';
const CURATION_RECORDS_MANAGER_CONTEXT = 'curation_records_manager';
const CURATION_RECORDS_STREAM_STATE = 'curation_records_manager';

const CURATION_RECORDS_MANAGER_ENABLED = booleanConf('curation_records_manager:enabled', true);
const CURATION_RECORDS_MANAGER_LOCK_KEY = conf.get('curation_records_manager:lock_key') || 'curation_records_manager_lock';
const CURATION_RECORDS_MANAGER_STREAM_LOCK_KEY = conf.get('curation_records_manager:stream_lock_key') || 'curation_records_manager_stream_lock';
const CURATION_RECORDS_MANAGER_INTERVAL = Number(conf.get('curation_records_manager:interval') ?? 60000);
const EXPIRY_INTERVAL_MS = 24 * 3600 * 1000;
const STREAM_MAX_ATTEMPTS = 5;
const RESTRICTION_RETRIES_PER_TICK = 50;
const RESTRICTION_RETRY_LOG_EVERY = 60;

let streamStartFrom: string | undefined;
let lastExpiryRun = 0;
let failedBatchKey: string | undefined;
let failedBatchAttempts = 0;

export const curationRecordsManagerCronHandler = async () => {
  const context = executionContext(CURATION_RECORDS_MANAGER_CONTEXT, CURATION_MANAGER_USER);
  streamStartFrom = (await redisGetManagerEventState(CURATION_RECORDS_STREAM_STATE)) ?? streamStartFrom;
  const pendingRecords = await completePendingMergeRecords(context);
  if (pendingRecords.completed + pendingRecords.discarded + pendingRecords.irreversible > 0) {
    logApp.warn('[CURATION] Pending merge records completed from the live graph', pendingRecords);
  }
  const retried = await retryQueuedRestrictionRefreshes(context);
  if (retried > 0) logApp.info('[CURATION] Queued restriction refreshes of curation records done', { count: retried });
  if (Date.now() - lastExpiryRun >= EXPIRY_INTERVAL_MS) {
    const expired = await expireMergeRecords(context);
    lastExpiryRun = Date.now();
    if (expired > 0) logApp.info('[CURATION] Merge records past their retention window closed', { count: expired });
  }
};

/**
 * The elements whose markings or organization sharing an event changes. A reclassified relationship also brings its
 * endpoints: the proposals whose action names it (an attribution in conflict) are found through their subjects.
 */
export const reclassifiedEntityIds = (streamEvents: Array<SseEvent<DataEvent>>): string[] => R.uniq(streamEvents.flatMap((streamEvent) => {
  const event = streamEvent.data as UpdateEvent;
  if (event.type !== EVENT_TYPE_UPDATE) return [];
  const extension = event.data?.extensions?.[STIX_EXT_OCTI] as { id?: string; source_ref?: string; target_ref?: string } | undefined;
  const reclassified = (event.context?.patch ?? []).some((operation: any) => typeof operation.path === 'string'
    && (operation.path.startsWith('/object_marking_refs') || operation.path.includes('/granted_refs')));
  if (!extension?.id || !reclassified) return [];
  return [extension.id, extension.source_ref, extension.target_ref].filter((id): id is string => typeof id === 'string' && id.length > 0);
}));

/**
 * The deleted elements. A deleted relationship also brings its endpoints: the proposals whose action names it (an
 * attribution in conflict) are found through their subjects.
 */
export const deletedEntityIds = (streamEvents: Array<SseEvent<DataEvent>>): string[] => R.uniq(streamEvents.flatMap((streamEvent) => {
  const event = streamEvent.data;
  if (event.type !== EVENT_TYPE_DELETE) return [];
  const extension = event.data?.extensions?.[STIX_EXT_OCTI] as { id?: string; source_ref?: string; target_ref?: string } | undefined;
  if (!extension?.id) return [];
  return [extension.id, extension.source_ref, extension.target_ref].filter((id): id is string => typeof id === 'string' && id.length > 0);
}));

const refreshRestrictions = async (context: AuthContext, entityIds: string[]) => {
  await refreshMergeRecordRestrictions(context, entityIds);
  await refreshProposalRestrictions(context, entityIds);
};

/**
 * The refreshes the stream could not make, retried at every cycle until they succeed: an entity stays queued, and an
 * error is logged at its first failed retry and then once an hour of retries. A queued entity was reclassified or
 * deleted: both upkeeps run, each leaving alone what does not concern it.
 */
export const retryQueuedRestrictionRefreshes = async (context: AuthContext) => {
  const queued = await redisCurationGetQueuedRestrictionRefreshes(RESTRICTION_RETRIES_PER_TICK);
  let refreshed = 0;
  for (let index = 0; index < queued.length; index += 1) {
    const { entityId } = queued[index];
    try {
      await refreshRestrictions(context, [entityId]);
      await retireProposalsOfDeletedSubjects(context, [entityId]);
      await redisCurationCompleteRestrictionRefresh(entityId);
      refreshed += 1;
    } catch (error) {
      const attempts = await redisCurationFailRestrictionRefresh(entityId);
      if (attempts === 1 || attempts % RESTRICTION_RETRY_LOG_EVERY === 0) {
        logApp.warn('[CURATION] Queued restriction refresh of curation records failed again', { cause: error, entity_id: entityId, attempts, manager: CURATION_RECORDS_MANAGER_ID });
      }
    }
  }
  return refreshed;
};

/**
 * The stream position is saved once the restrictions of a batch are refreshed. A failing batch is processed again
 * from the saved position (a refresh is idempotent); after STREAM_MAX_ATTEMPTS failures in a row its entities are
 * refreshed one by one, and an entity that still fails is logged so the batch does not block the stream.
 */
export const curationRecordsManagerStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>, lastEventId: string) => {
  const context = executionContext(CURATION_RECORDS_MANAGER_CONTEXT, CURATION_MANAGER_USER);
  const entityIds = reclassifiedEntityIds(streamEvents);
  const deletedIds = deletedEntityIds(streamEvents);
  const batchKey = streamEvents[0]?.id ?? 'empty';
  try {
    if (entityIds.length > 0) await refreshRestrictions(context, entityIds);
    if (deletedIds.length > 0) {
      const retired = await retireProposalsOfDeletedSubjects(context, deletedIds);
      if (retired > 0) logApp.info('[CURATION] Open proposals about deleted entities removed', { count: retired });
    }
  } catch (error) {
    failedBatchAttempts = failedBatchKey === batchKey ? failedBatchAttempts + 1 : 1;
    failedBatchKey = batchKey;
    if (failedBatchAttempts < STREAM_MAX_ATTEMPTS) {
      logApp.warn('[CURATION] Restriction refresh failed, the batch will be processed again', { cause: error, attempt: failedBatchAttempts, first_event_id: batchKey });
      throw error;
    }
    const failedIds: string[] = [];
    for (let index = 0; index < entityIds.length; index += 1) {
      try {
        await refreshRestrictions(context, [entityIds[index]]);
      } catch (entityError) {
        failedIds.push(entityIds[index]);
        logApp.warn('[CURATION] Restrictions of curation records not refreshed for an entity, queued for a retry', { cause: entityError, entity_id: entityIds[index], manager: CURATION_RECORDS_MANAGER_ID });
      }
    }
    for (let index = 0; index < deletedIds.length; index += 1) {
      try {
        await retireProposalsOfDeletedSubjects(context, [deletedIds[index]]);
      } catch (entityError) {
        failedIds.push(deletedIds[index]);
        logApp.warn('[CURATION] Open proposals about a deleted entity not removed, queued for a retry', { cause: entityError, entity_id: deletedIds[index], manager: CURATION_RECORDS_MANAGER_ID });
      }
    }
    // Queued before the stream position moves on: if the queue cannot be written, the batch is processed again.
    await redisCurationQueueRestrictionRefresh(failedIds);
  }
  failedBatchKey = undefined;
  failedBatchAttempts = 0;
  streamStartFrom = lastEventId;
  await redisSetManagerEventState(CURATION_RECORDS_STREAM_STATE, lastEventId);
};

const CURATION_RECORDS_MANAGER_DEFINITION: ManagerDefinition = {
  id: CURATION_RECORDS_MANAGER_ID,
  label: CURATION_RECORDS_MANAGER_LABEL,
  executionContext: CURATION_RECORDS_MANAGER_CONTEXT,
  enabledByConfig: CURATION_RECORDS_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  cronSchedulerHandler: {
    handler: curationRecordsManagerCronHandler,
    interval: CURATION_RECORDS_MANAGER_INTERVAL,
    lockKey: CURATION_RECORDS_MANAGER_LOCK_KEY,
    runOnStart: true,
  },
  streamSchedulerHandler: {
    handler: curationRecordsManagerStreamHandler,
    interval: CURATION_RECORDS_MANAGER_INTERVAL,
    lockKey: CURATION_RECORDS_MANAGER_STREAM_LOCK_KEY,
    streamOpts: { withInternal: false, bufferTime: 5000 },
    streamProcessorStartFrom: () => streamStartFrom ?? 'live',
  },
};

registerManager(CURATION_RECORDS_MANAGER_DEFINITION);
