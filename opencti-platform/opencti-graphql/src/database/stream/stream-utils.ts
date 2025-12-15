import * as jsonpatch from 'fast-json-patch';
import type { AuthUser } from '../../types/user';
import type { StoreObject } from '../../types/store';
import { generateMergeMessage } from '../generate-message';
import { convertStoreToStix_2_1 } from '../stix-2-1-converter';
import type { StixCoreObject, StixObject } from '../../types/stix-2-1-common';
import { asyncListTransformation, EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from '../utils';
import { UnsupportedError } from '../../config/errors';
import { INTERNAL_EXPORTABLE_TYPES } from '../../schema/stixCoreObject';
import type {
  ActivityStreamEvent,
  BaseEvent,
  Change,
  DeleteEvent,
  EventOpts,
  MergeEvent,
  SseEvent,
  StreamDataEvent,
  StreamNotifEvent,
  UpdateEvent,
  UpdateEventOpts,
} from '../../types/event';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const LIVE_STREAM_NAME = 'stream.opencti';
export const NOTIFICATION_STREAM_NAME = 'stream.notification';
export const ACTIVITY_STREAM_NAME = 'stream.activity';
export const EVENT_CURRENT_VERSION = '4';
export const EVENT_ACTIVITY_VERSION = '1';

export interface StreamProcessor {
  info: () => Promise<object>;
  start: (from: string | undefined) => Promise<void>;
  shutdown: () => Promise<void>;
  running: () => boolean;
}

export enum StreamProvider {
  BASE = 'base',
  PIR = 'Pir Manager',
}

export interface StreamOption {
  withInternal?: boolean;
  bufferTime?: number;
  autoReconnect?: boolean;
  streamName?: string;
  streamBatchSize?: number;
}

export type StreamInfo = {
  lastEventId: string;
  firstEventId: string;
  firstEventDate: string;
  lastEventDate: string;
  streamSize: number;
};

export interface RawStreamClient {
  initializeStreams: () => Promise<void>;
  rawPushToStream: <T extends BaseEvent> (event: T) => Promise<void>;
  rawFetchStreamInfo: (streamName?: string) => Promise<StreamInfo>;
  rawCreateStreamProcessor: <T extends BaseEvent> (
    provider: string,
    callback: (events: Array<SseEvent<T>>, lastEventId: string) => Promise<void>,
    opts?: StreamOption,
  ) => StreamProcessor;
  rawFetchStreamEventsRangeFromEventId: <T extends BaseEvent> (
    startEventId: string,
    callback: (events: Array<SseEvent<T>>, lastEventId: string) => void,
    opts?: StreamOption,
  ) => Promise<{ lastEventId: string }>;
  rawStoreNotificationEvent: <T extends StreamNotifEvent> (event: T) => Promise<void>;
  rawFetchRangeNotifications: <T extends StreamNotifEvent> (start: Date, end: Date) => Promise<Array<T>>;
  rawStoreActivityEvent: (event: ActivityStreamEvent) => Promise<void>;
}

export const isStreamPublishable = (opts: EventOpts) => {
  return opts.publishStreamEvent === undefined || opts.publishStreamEvent;
};
// Merge
export const buildMergeEvent = async (user: AuthUser, previous: StoreObject, instance: StoreObject, sourceEntities: Array<StoreObject>): Promise<MergeEvent> => {
  const message = generateMergeMessage(instance, sourceEntities);
  const previousStix = convertStoreToStix_2_1(previous) as StixCoreObject;
  const currentStix = convertStoreToStix_2_1(instance) as StixCoreObject;
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_MERGE,
    scope: 'external',
    message,
    origin: user.origin,
    data: currentStix,
    context: {
      patch: jsonpatch.compare(previousStix, currentStix),
      reverse_patch: jsonpatch.compare(currentStix, previousStix),
      sources: await asyncListTransformation<StixObject>(sourceEntities, convertStoreToStix_2_1) as StixCoreObject[],
    },
  };
};
// Update
export const buildStixUpdateEvent = (
  user: AuthUser,
  previousStix: StixCoreObject,
  stix: StixCoreObject,
  message: string,
  changes: Change[],
  opts: UpdateEventOpts = {},
): UpdateEvent => {
  // Build and send the event
  const patch = jsonpatch.compare(previousStix, stix);
  const previousPatch = jsonpatch.compare(stix, previousStix);
  if (patch.length === 0 || previousPatch.length === 0) {
    throw UnsupportedError('Update event must contains a valid previous patch');
  }
  if (patch.length === 1 && patch[0].path === '/modified' && !opts.allow_only_modified) {
    throw UnsupportedError('Update event must contains more operation than just modified/updated_at value');
  }
  const entityType = stix.extensions[STIX_EXT_OCTI].type;
  const scope = INTERNAL_EXPORTABLE_TYPES.includes(entityType) ? 'internal' : 'external';
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_UPDATE,
    scope,
    message,
    origin: user.origin,
    data: stix,
    commit: opts.commit,
    noHistory: opts.noHistory,
    context: {
      patch,
      reverse_patch: previousPatch,
      related_restrictions: opts.related_restrictions,
      pir_ids: opts.pir_ids,
      changes,
    },
  };
};
export const buildUpdateEvent = (user: AuthUser, previous: StoreObject, instance: StoreObject, message: string, changes: Change[], opts: UpdateEventOpts): UpdateEvent => {
  // Build and send the event
  const stix = convertStoreToStix_2_1(instance) as StixCoreObject;
  const previousStix = convertStoreToStix_2_1(previous) as StixCoreObject;
  return buildStixUpdateEvent(user, previousStix, stix, message, changes, opts);
};
// Create
export const buildCreateEvent = (user: AuthUser, instance: StoreObject, message: string): StreamDataEvent => {
  const stix = convertStoreToStix_2_1(instance) as StixCoreObject;
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_CREATE,
    scope: INTERNAL_EXPORTABLE_TYPES.includes(instance.entity_type) ? 'internal' : 'external',
    message,
    origin: user.origin,
    data: stix,
  };
};
// Delete
export const buildDeleteEvent = async (
  user: AuthUser,
  instance: StoreObject,
  message: string,
): Promise<DeleteEvent> => {
  const stix = convertStoreToStix_2_1(instance) as StixCoreObject;
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_DELETE,
    scope: INTERNAL_EXPORTABLE_TYPES.includes(instance.entity_type) ? 'internal' : 'external',
    message,
    origin: user.origin,
    data: stix,
  };
};
