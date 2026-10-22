import { ATTR_DB_NAMESPACE, SEMATTRS_DB_NAME } from '@opentelemetry/semantic-conventions';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicWorkflowStatus, StoreObject, StoreRelation } from '../../types/store';
import type { ActivityStreamEvent, BaseEvent, Change, CreateEventOpts, EventOpts, SseEvent, StreamDataEvent, StreamNotifEvent, UpdateEventOpts } from '../../types/event';
import { isStixExportableInStreamData } from '../../schema/stixCoreObject';
import { generateCreateMessage, generateDeleteMessage, generateRestoreMessage } from '../data-changes';
import {
  buildCreateEvent,
  buildDeleteEvent,
  buildMergeEvent,
  buildUpdateEvent,
  type FetchEventRangeOption,
  isStreamPublishable,
  LIVE_STREAM_NAME,
  type RawStreamClient,
  type SizedNotifEvent,
  STREAM_FULL_DEBUG_ACTIVATED,
  type StreamProcessor,
  type StreamProcessorOption,
} from './stream-utils';
import { DatabaseError } from '../../config/errors';
import { getDraftContext } from '../../utils/draftContext';
import { rawRedisStreamClient } from '../redis-stream';
import { telemetry } from '../../config/tracing';
import { booleanConf, logApp } from '../../config/conf';
import { getEntitiesMapFromCache } from '../cache';
import { ENTITY_TYPE_STATUS } from '../../schema/internalObject';

const streamClient: RawStreamClient = rawRedisStreamClient;
export const initializeStreamStack = async () => {
  if (streamClient.initializeStreams) {
    await streamClient.initializeStreams();
  }
};

const resolveWorkflowStatusName = async (context: AuthContext, user: AuthUser, instance: StoreObject): Promise<{ name: string; scope: string } | undefined> => {
  const workflowId = instance.x_opencti_workflow_id;
  if (!workflowId) return undefined;
  try {
    const platformStatuses = await getEntitiesMapFromCache<BasicWorkflowStatus>(context, user, ENTITY_TYPE_STATUS);
    const status = platformStatuses.get(workflowId);
    return status?.name ? { name: status.name, scope: status.scope } : undefined;
  } catch (e) {
    logApp.warn('[OPENCTI] Unable to resolve workflow status name for stream event', { error: e });
    return undefined;
  }
};

const pushToStream = async <T extends BaseEvent> (context: AuthContext, user: AuthUser, event: T, opts: EventOpts = {}) => {
  const draftContext = getDraftContext(context, user);
  const eventToPush = { ...event, event_id: context.eventId };
  if (!draftContext && isStreamPublishable(opts)) {
    if (STREAM_FULL_DEBUG_ACTIVATED) {
      logApp.info('Pushing event to stream', { event: eventToPush });
    }
    const pushToStreamFn = async () => {
      await streamClient.rawPushToStream(eventToPush);
    };
    await telemetry(context, user, 'INSERT STREAM', {
      [ATTR_DB_NAMESPACE]: 'stream_engine',
      // Deprecated attribute to be removed when transition done
      [SEMATTRS_DB_NAME]: 'stream_engine',
    }, pushToStreamFn);
  }
};

const pushManyToStream = async <T extends BaseEvent> (context: AuthContext, user: AuthUser, events: T[], opts: EventOpts = {}) => {
  if (events.length === 0 || getDraftContext(context, user) || !isStreamPublishable(opts)) {
    return;
  }
  const eventsToPush = events.map((event) => ({ ...event, event_id: context.eventId }));
  if (STREAM_FULL_DEBUG_ACTIVATED) {
    logApp.info('Pushing events to stream', { events: eventsToPush });
  }
  const pushManyToStreamFn = async () => {
    await streamClient.rawPushManyToStream(eventsToPush);
  };
  await telemetry(context, user, 'INSERT STREAM', {
    [ATTR_DB_NAMESPACE]: 'stream_engine',
    // Deprecated attribute to be removed when transition done
    [SEMATTRS_DB_NAME]: 'stream_engine',
  }, pushManyToStreamFn);
};

export const publishStixToStream = async (context: AuthContext, user: AuthUser, event: StreamDataEvent) => {
  await pushToStream(context, user, event);
};

// The lock-free write path keeps its identity index in step with what today's path writes (lockfree/ingestion.ts),
// loaded on first use: it depends on the middleware, which depends on this file
const LOCKFREE_INGESTION_ENABLED = booleanConf('app:lockfree_ingestion:enabled', false);
const lockFreeSync = () => import('../lockfree/ingestion');

export const storeMergeEvent = async (
  context: AuthContext,
  user: AuthUser,
  initialInstance: StoreObject,
  mergedInstance: StoreObject,
  sourceEntities: Array<StoreObject>,
  opts: EventOpts,
) => {
  try {
    const event = await buildMergeEvent(user, initialInstance, mergedInstance, sourceEntities);
    await pushToStream(context, user, event, opts);
    if (LOCKFREE_INGESTION_ENABLED) await (await lockFreeSync()).syncIdentityOnMerge(context, user, mergedInstance, sourceEntities);
    return event;
  } catch (e) {
    throw DatabaseError('Error in store merge event', { cause: e });
  }
};
export const storeUpdateEvent = async (
  context: AuthContext,
  user: AuthUser,
  previous: StoreObject,
  instance: StoreObject,
  changes: Change[],
  opts: UpdateEventOpts = {},
) => {
  try {
    if (isStixExportableInStreamData(instance)) {
      const [previousStatus, currentStatus] = await Promise.all([
        resolveWorkflowStatusName(context, user, previous),
        resolveWorkflowStatusName(context, user, instance),
      ]);
      const workflowStatuses = { previous: previousStatus, current: currentStatus };
      const event = buildUpdateEvent(user, previous, instance, changes, opts, workflowStatuses);
      await pushToStream(context, user, event, opts);
      if (LOCKFREE_INGESTION_ENABLED) await (await lockFreeSync()).syncIdentityOnUpdate(context, user, instance);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store update event', { cause: e });
  }
};

export const storeCreateRelationEvent = async (context: AuthContext, user: AuthUser, instance: StoreRelation, opts: CreateEventOpts = {}) => {
  try {
    if (isStixExportableInStreamData(instance)) {
      const { withoutMessage = false, restore = false } = opts;
      let message = '-';
      if (!withoutMessage) {
        message = restore ? generateRestoreMessage(instance) : generateCreateMessage(instance);
      }
      const workflowStatus = await resolveWorkflowStatusName(context, user, instance);
      const event = buildCreateEvent(user, instance, message, workflowStatus);
      await pushToStream(context, user, event, opts);
      if (LOCKFREE_INGESTION_ENABLED) await (await lockFreeSync()).syncIdentityOnCreate(context, user, instance);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create relation event', { cause: e });
  }
};

export const storeCreateEntityEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, message: string, opts: CreateEventOpts = {}) => {
  try {
    if (isStixExportableInStreamData(instance)) {
      const workflowStatus = await resolveWorkflowStatusName(context, user, instance);
      const event = buildCreateEvent(user, instance, message, workflowStatus);
      await pushToStream(context, user, event, opts);
      if (LOCKFREE_INGESTION_ENABLED) await (await lockFreeSync()).syncIdentityOnCreate(context, user, instance);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create entity event', { cause: e });
  }
};
// Create events of objects written together, as storeCreateEntityEvent / storeCreateRelationEvent build them,
// pushed in one round trip and in the order given. Relationships without a message get the generated one.
export const storeCreateEvents = async (
  context: AuthContext,
  user: AuthUser,
  items: { instance: StoreObject; message?: string }[],
  opts: CreateEventOpts = {},
) => {
  try {
    const exportable = items.filter(({ instance }) => isStixExportableInStreamData(instance));
    const events = await Promise.all(exportable.map(async ({ instance, message }) => {
      const workflowStatus = await resolveWorkflowStatusName(context, user, instance);
      return buildCreateEvent(user, instance, message ?? generateCreateMessage(instance), workflowStatus);
    }));
    await pushManyToStream(context, user, events, opts);
    return events;
  } catch (e) {
    throw DatabaseError('Error in store create events', { cause: e });
  }
};
export const storeDeleteEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, opts: EventOpts = {}) => {
  try {
    if (isStixExportableInStreamData(instance)) {
      const message = generateDeleteMessage(instance);
      const event = await buildDeleteEvent(user, instance, message);
      await pushToStream(context, user, event, opts);
      if (LOCKFREE_INGESTION_ENABLED) await (await lockFreeSync()).syncIdentityOnDelete(context, user, instance);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store delete event', { cause: e });
  }
};

export const createStreamProcessor = <T extends BaseEvent> (
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
  opts: StreamProcessorOption = {},
): StreamProcessor => {
  return streamClient.rawCreateStreamProcessor(provider, callback, opts);
};

export const fetchStreamInfo = async (streamName = LIVE_STREAM_NAME) => {
  return streamClient.rawFetchStreamInfo(streamName);
};

export const fetchStreamEventsRangeFromEventId = async <T extends BaseEvent> (
  startEventId: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => void,
  opts: FetchEventRangeOption = {},
) => {
  return streamClient.rawFetchStreamEventsRangeFromEventId(startEventId, callback, opts);
};

// region opencti notification stream
export const storeNotificationEvent = async <T extends StreamNotifEvent>(_context: AuthContext, event: T) => {
  await streamClient.rawStoreNotificationEvent(event);
};
export const fetchRangeNotifications = async <T extends StreamNotifEvent>(
  start: Date,
  end: Date,
  callback: (events: Array<SizedNotifEvent<T>>) => Promise<boolean | void> | boolean | void,
): Promise<void> => {
  return streamClient.rawFetchRangeNotifications<T>(start, end, callback);
};
// endregion
// region opencti audit stream
export const storeActivityEvent = async (event: ActivityStreamEvent) => {
  await streamClient.rawStoreActivityEvent(event);
};
// endregion
