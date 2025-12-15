import { SEMATTRS_DB_NAME } from '@opentelemetry/semantic-conventions';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StoreObject, StoreRelation } from '../../types/store';
import type { ActivityStreamEvent, BaseEvent, Change, CreateEventOpts, EventOpts, SseEvent, StreamDataEvent, StreamNotifEvent, UpdateEventOpts } from '../../types/event';
import { isStixExportableInStreamData } from '../../schema/stixCoreObject';
import { generateCreateMessage, generateDeleteMessage, generateRestoreMessage } from '../generate-message';
import {
  buildCreateEvent,
  buildDeleteEvent,
  buildMergeEvent,
  buildUpdateEvent,
  isStreamPublishable,
  LIVE_STREAM_NAME,
  type RawStreamClient,
  type StreamOption,
  type StreamProcessor,
} from './stream-utils';
import { DatabaseError } from '../../config/errors';
import { getDraftContext } from '../../utils/draftContext';
import { rawRedisStreamClient } from '../redis-stream';
import { telemetry } from '../../config/tracing';

const streamClient: RawStreamClient = rawRedisStreamClient;
export const initializeStreamStack = async () => {
  if (streamClient.initializeStreams) {
    await streamClient.initializeStreams();
  }
};

const pushToStream = async <T extends BaseEvent> (context: AuthContext, user: AuthUser, event: T, opts: EventOpts = {}) => {
  const draftContext = getDraftContext(context, user);
  const eventToPush = { ...event, event_id: context.eventId };
  if (!draftContext && isStreamPublishable(opts)) {
    const pushToStreamFn = async () => {
      await streamClient.rawPushToStream(eventToPush);
    };
    await telemetry(context, user, 'INSERT STREAM', {
      [SEMATTRS_DB_NAME]: 'stream_engine',
    }, pushToStreamFn);
  }
};

export const publishStixToStream = async (context: AuthContext, user: AuthUser, event: StreamDataEvent) => {
  await pushToStream(context, user, event);
};

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
  message: string,
  changes: Change[],
  opts: UpdateEventOpts = {},
) => {
  try {
    if (isStixExportableInStreamData(instance)) {
      const event = buildUpdateEvent(user, previous, instance, message, changes, opts);
      await pushToStream(context, user, event, opts);
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
      const event = buildCreateEvent(user, instance, message);
      await pushToStream(context, user, event, opts);
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
      const event = buildCreateEvent(user, instance, message);
      await pushToStream(context, user, event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create entity event', { cause: e });
  }
};
export const storeDeleteEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, opts: EventOpts = {}) => {
  try {
    if (isStixExportableInStreamData(instance)) {
      const message = generateDeleteMessage(instance);
      const event = await buildDeleteEvent(user, instance, message);
      await pushToStream(context, user, event, opts);
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
  opts: StreamOption = {},
): StreamProcessor => {
  return streamClient.rawCreateStreamProcessor(provider, callback, opts);
};

export const fetchStreamInfo = async (streamName = LIVE_STREAM_NAME) => {
  return streamClient.rawFetchStreamInfo(streamName);
};

export const fetchStreamEventsRangeFromEventId = async <T extends BaseEvent> (
  startEventId: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => void,
  opts: StreamOption = {},
) => {
  return streamClient.rawFetchStreamEventsRangeFromEventId(startEventId, callback, opts);
};

// region opencti notification stream
export const storeNotificationEvent = async <T extends StreamNotifEvent>(_context: AuthContext, event: T) => {
  await streamClient.rawStoreNotificationEvent(event);
};
export const fetchRangeNotifications = async <T extends StreamNotifEvent>(start: Date, end: Date): Promise<Array<T>> => {
  return streamClient.rawFetchRangeNotifications<T>(start, end);
};
// endregion
// region opencti audit stream
export const storeActivityEvent = async (event: ActivityStreamEvent) => {
  await streamClient.rawStoreActivityEvent(event);
};
// endregion
