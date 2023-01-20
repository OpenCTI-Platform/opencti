import { readFileSync } from 'node:fs';
import Redis, { RedisOptions } from 'ioredis';
import Redlock from 'redlock';
import * as jsonpatch from 'fast-json-patch';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
import type { ChainableCommander } from 'ioredis/built/utils/RedisCommander';
import { SemanticAttributes } from '@opentelemetry/semantic-conventions';
import conf, { booleanConf, configureCA, DEV_MODE, ENABLED_CACHING, getStoppingState, logApp } from '../config/conf';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_MERGE,
  EVENT_TYPE_UPDATE,
  generateCreateMessage,
  generateDeleteMessage,
  generateMergeMessage,
  isEmptyField,
  waitInSec,
} from './utils';
import { isStixExportableData } from '../schema/stixCoreObject';
import { DatabaseError, FunctionalError, UnsupportedError } from '../config/errors';
import { now, utcDate } from '../utils/format';
import RedisStore, { REDIS_PREFIX } from './sessionStore-redis';
import SessionStoreMemory from './sessionStore-memory';
import { getInstanceIds } from '../schema/identifier';
import { convertStoreToStix } from './stix-converter';
import type { StoreObject, StoreRelation } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import type {
  BaseEvent,
  CreateEventOpts,
  DeleteEvent,
  EventOpts,
  MergeEvent, SseEvent,
  StreamDataEvent,
  UpdateEvent,
  UpdateEventOpts
} from '../types/event';
import type { StixCoreObject } from '../types/stix-common';
import type { EditContext } from '../generated/graphql';
import { telemetry } from '../config/tracing';
import { filterEmpty } from '../types/type-utils';
import type { ClusterConfig } from '../manager/clusterManager';

const USE_SSL = booleanConf('redis:use_ssl', false);
const REDIS_CA = conf.get('redis:ca').map((path: string) => readFileSync(path));
export const REDIS_STREAM_NAME = `${REDIS_PREFIX}stream.opencti`;
export const NOTIFICATION_STREAM_NAME = `${REDIS_PREFIX}stream.notification`;

export const EVENT_CURRENT_VERSION = '4';
const BASE_DATABASE = 0; // works key for tracking / stream
const CONTEXT_DATABASE = 1; // locks / user context
const REDIS_EXPIRE_TIME = 90;
const MAX_RETRY_COMMAND = 10;

const isStreamPublishable = (opts: EventOpts) => {
  return opts.publishStreamEvent === undefined || opts.publishStreamEvent;
};

const redisOptions = (database: number): RedisOptions => ({
  keyPrefix: REDIS_PREFIX,
  db: database,
  port: conf.get('redis:port'),
  host: conf.get('redis:hostname'),
  username: conf.get('redis:username'),
  password: conf.get('redis:password'),
  tls: USE_SSL ? { ...configureCA(REDIS_CA), servername: conf.get('redis:hostname') } : undefined,
  retryStrategy: /* istanbul ignore next */ (times) => {
    if (getStoppingState()) return null;
    return Math.min(times * 50, 2000);
  },
  lazyConnect: true,
  enableAutoPipelining: false,
  enableOfflineQueue: true,
  maxRetriesPerRequest: MAX_RETRY_COMMAND,
  showFriendlyErrorStack: DEV_MODE,
});

const createRedisClient = (provider: string, database?: number): Redis => {
  const client = new Redis(redisOptions(database ?? BASE_DATABASE));
  client.on('close', () => logApp.info(`[REDIS] Redis '${provider}' client closed`));
  client.on('ready', () => logApp.info(`[REDIS] Redis '${provider}' client ready`));
  client.on('error', (err) => logApp.error(`[REDIS] Redis '${provider}' client error`, { error: err }));
  client.on('reconnecting', () => logApp.info(`[REDIS] '${provider}' Redis client reconnecting`));
  client.defineCommand('cacheGet', {
    lua:
        'local index = 1\n'
        + 'local resolvedKeys = redis.call(\'mget\', unpack(KEYS))\n'
        + 'for p, k in pairs(resolvedKeys) do \n'
        + '    if (k==nil or (type(k) == "boolean" and not k)) then \n'
        + '        index = index+1\n'
        + '    elseif (k:sub(0, 1) == "@") then \n'
        + '        local subKey = "cache:" .. k:sub(2, #k)\n'
        + '        resolvedKeys[index] = redis.call(\'get\', subKey)\n'
        + '        index = index+1\n'
        + '    else \n'
        + '        index = index+1\n'
        + '    end\n'
        + 'end\n'
        + 'return resolvedKeys\n',
  });
  return client;
};

const clientBase = createRedisClient('Client base');
const clientCache = createRedisClient('Client cache');
const clientContext = createRedisClient('Client context', CONTEXT_DATABASE);
const clientPublisher = createRedisClient('Pubsub publisher');
const clientSubscriber = createRedisClient('Pubsub subscriber');

export const pubsub = new RedisPubSub({ publisher: clientPublisher as any, subscriber: clientSubscriber as any });
export const createMemorySessionStore = () => {
  return new SessionStoreMemory({
    checkPeriod: 3600000, // prune expired entries every 1h
  });
};
export const createRedisSessionStore = () => {
  return new RedisStore(clientContext, {
    ttl: conf.get('app:session_timeout'),
  });
};

export const redisIsAlive = async () => {
  try {
    const client = new Redis({
      keyPrefix: REDIS_PREFIX,
      db: BASE_DATABASE,
      port: conf.get('redis:port'),
      host: conf.get('redis:hostname'),
      username: conf.get('redis:username'),
      password: conf.get('redis:password'),
      tls: USE_SSL ? { ...configureCA(REDIS_CA), servername: conf.get('redis:hostname') } : undefined,
      lazyConnect: true,
      maxRetriesPerRequest: 0,
      showFriendlyErrorStack: DEV_MODE,
    });
    client.on('error', () => undefined /* do nothing */);
    await client.get('test-key');
    client.disconnect();
  } catch {
    throw DatabaseError('Redis seems down');
  }
  return true;
};
export const getRedisVersion = async () => {
  const serverInfo = await clientBase.call('INFO') as string;
  const versionString = serverInfo.split('\r\n')[1];
  return versionString.split(':')[1];
};

/* istanbul ignore next */
export const notify = (topic: string, instance: any, user: AuthUser) => {
  // Instance can be empty if user is currently looking for a deleted instance
  if (instance) {
    pubsub.publish(topic, { instance, user });
  }
  return instance;
};

// region user context (clientContext)
const contextFetchMatch = async (match: string): Promise<Array<string>> => {
  return new Promise((resolve, reject) => {
    const elementsPromise: Array<Promise<any>> = [];
    const stream = clientContext.scanStream({
      match: `${REDIS_PREFIX}${match}`,
      count: 100,
    });
    stream.on('data', (resultKeys) => {
      for (let i = 0; i < resultKeys.length; i += 1) {
        const resultKey = resultKeys[i];
        elementsPromise.push(clientContext.call('GET', resultKey).then((d) => ({ key: resultKey, value: d })));
      }
    });
    stream.on('error', (error) => {
      /* istanbul ignore next */
      reject(error);
    });
    stream.on('end', () => {
      Promise.all(elementsPromise).then((data) => {
        const elements = R.map((d) => ({ redis_key: d.key, ...JSON.parse(d.value) }), data);
        resolve(elements);
      });
    });
  });
};
export const setEditContext = async (user: AuthUser, instanceId: string, input: EditContext) => {
  const data = R.assoc('name', user.user_email, input);
  return clientContext.set(
    `edit:${instanceId}:${user.id}`,
    JSON.stringify(data),
    'EX',
    5 * 60 // Key will be remove if user is not active during 5 minutes
  );
};
export const fetchEditContext = async (instanceId: string) => {
  return contextFetchMatch(`edit:${instanceId}:*`);
};
export const delEditContext = async (user: AuthUser, instanceId: string) => {
  return clientContext.del(`edit:${instanceId}:${user.id}`);
};
export const delUserContext = async (user: AuthUser) => {
  return new Promise((resolve, reject) => {
    const stream = clientContext.scanStream({ match: `${REDIS_PREFIX}*:*:${user.id}`, count: 100 });
    const keys: Array<any> = [];
    stream.on('data', (resultKeys) => {
      for (let index = 0; index < resultKeys.length; index += 1) {
        keys.push(resultKeys[index]);
      }
    });
    stream.on('error', (error) => {
      /* istanbul ignore next */
      reject(error);
    });
    stream.on('end', () => {
      if (!R.isEmpty(keys)) {
        clientContext.call('DEL', keys);
      }
      resolve(true);
    });
  });
};
// endregion

// region basic operations
export const redisTx = async (client: Redis, chain: (tx: ChainableCommander) => void) => {
  const tx = client.multi();
  try {
    await chain(tx);
    return await tx.exec();
  } catch (e) {
    throw DatabaseError('Redis Tx error', { error: e });
  }
};
const updateObjectRaw = async (tx: ChainableCommander, id: string, input: object) => {
  const data = R.flatten(R.toPairs(input));
  await tx.hset(id, data);
};
const updateObjectCounterRaw = async (tx: ChainableCommander, id: string, field: string, number: number) => {
  await tx.hincrby(id, field, number);
};
// endregion

// region concurrent deletion
export const redisAddDeletions = async (internalIds: Array<string>) => {
  const deletionId = new Date().getTime();
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  return redisTx(clientContext, (tx) => {
    tx.setex(`deletion-${deletionId}`, REDIS_EXPIRE_TIME, JSON.stringify(ids));
  });
};
export const redisFetchLatestDeletions = async () => {
  const keys = await contextFetchMatch('deletion-*');
  return R.uniq(R.flatten(keys));
};
// endregion

// region locking (clientContext)
const checkParticipantsDeletion = async (participantIds: Array<string>) => {
  const latestDeletions = await redisFetchLatestDeletions();
  const deletedParticipantsIds = participantIds.filter((x) => latestDeletions.includes(x));
  if (deletedParticipantsIds.length > 0) {
    // noinspection ExceptionCaughtLocallyJS
    throw FunctionalError('Cant update an element based on deleted dependencies', { deletedParticipantsIds });
  }
};
export const lockResource = async (resources: Array<string>, automaticExtension = true) => {
  let timeout: NodeJS.Timeout | undefined;
  const locks = R.uniq(resources);
  const automaticExtensionThreshold = conf.get('app:concurrency:extension_threshold');
  const retryCount = conf.get('app:concurrency:retry_count');
  const retryDelay = conf.get('app:concurrency:retry_delay');
  const retryJitter = conf.get('app:concurrency:retry_jitter');
  const maxTtl = conf.get('app:concurrency:max_ttl');
  const redlock = new Redlock([clientContext], { retryCount, retryDelay, retryJitter });
  // Get the lock
  const lock = await redlock.acquire(locks, maxTtl); // Force unlock after maxTtl
  let expiration = Date.now() + maxTtl;
  const extend = async () => {
    try {
      await lock.extend(maxTtl);
      expiration = Date.now() + maxTtl;
      if (automaticExtension) {
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        queue();
      }
    } catch (e) {
      logApp.debug('[REDIS] Failed to extend resource', { locks });
    }
  };
  const queue = () => {
    const timeToWait = expiration - Date.now() - automaticExtensionThreshold;
    timeout = setTimeout(() => extend(), timeToWait);
  };
  if (automaticExtension) {
    queue();
  }
  // If lock succeed we need to be sure that delete occurred just before the resolution/lock
  await checkParticipantsDeletion(resources);
  // Return the lock and capable actions
  return {
    extend,
    unlock: async () => {
      // First clear the auto extends if needed
      if (timeout) {
        clearTimeout(timeout);
        timeout = undefined;
      }
      // Then unlock in redis
      try {
        // Only try to unlock if redis connection is ready
        if (clientContext.status === 'ready') {
          await lock.release();
        }
      } catch (e) {
        logApp.warn('[REDIS] Failed to unlock resource', { locks });
      }
    },
  };
};
// endregion

// region cache
const cacheExtraIds = (e: StoreObject) => getInstanceIds(e, true).map((i) => `cache:${i}`);
export const cacheSet = async (elements: Array<StoreObject>) => {
  if (ENABLED_CACHING) {
    await redisTx(clientCache, (tx) => {
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        tx.set(`cache:${element.internal_id}`, JSON.stringify(element), 'EX', 5 * 60);
        const ids = cacheExtraIds(element);
        for (let indexId = 0; indexId < ids.length; indexId += 1) {
          const id = ids[indexId];
          tx.set(id, `@${element.internal_id}`, 'EX', 5 * 60);
        }
      }
    });
  }
};
export const cacheDel = async (elements: Array<StoreObject>) => {
  if (ENABLED_CACHING) {
    const ids = R.flatten(elements.map((e) => [`cache:${e.internal_id}`, ...cacheExtraIds(e)]));
    await clientCache.del(ids);
  }
};
export const cachePurge = async () => {
  if (ENABLED_CACHING) {
    const keys = await clientCache.keys('cache:*');
    if (keys && keys.length > 0) {
      await clientCache.del(keys);
    }
  }
};
export const cacheGet = async (id: string | Array<string>): Promise<StoreObject | undefined> => {
  const ids = Array.isArray(id) ? id : [id];
  if (ENABLED_CACHING) {
    const result: any = {};
    if (ids.length > 0) {
      const client = clientCache as any; // TODO JRI Find a way to not use any
      const keyValues = await client.cacheGet(ids.length, ids.map((i) => `cache:${i}`));
      for (let index = 0; index < ids.length; index += 1) {
        const val = keyValues[index];
        result[ids[index]] = val ? JSON.parse(val) : val;
      }
    }
    return result;
  }
  return undefined;
};
// endregion

// region opencti data stream
const streamTrimming = conf.get('redis:trimming') || 0;
const notificationTrimming = conf.get('redis:notification_trimming') || 50000;
const mapJSToStream = (event: any) => {
  const cmdArgs: Array<string> = [];
  Object.keys(event).forEach((key) => {
    const value = event[key];
    if (value !== undefined) {
      cmdArgs.push(key);
      cmdArgs.push(JSON.stringify(value));
    }
  });
  return cmdArgs;
};
const pushToStream = async (context: AuthContext, user: AuthUser, client: Redis, event: BaseEvent, opts: EventOpts = {}) => {
  if (isStreamPublishable(opts)) {
    const pushToStreamFn = async () => {
      if (streamTrimming) {
        await client.call('XADD', REDIS_STREAM_NAME, 'MAXLEN', '~', streamTrimming, '*', ...mapJSToStream(event));
      } else {
        await client.call('XADD', REDIS_STREAM_NAME, '*', ...mapJSToStream(event));
      }
    };
    telemetry(context, user, 'INSERT STREAM', {
      [SemanticAttributes.DB_NAME]: 'stream_engine',
    }, pushToStreamFn);
  }
};

// Merge
interface MergeImpacts {
  updatedRelations: Array<string>;
  dependencyDeletions: Array<StoreObject>;
}

const buildMergeEvent = (user: AuthUser, previous: StoreObject, instance: StoreObject, sourceEntities: Array<StoreObject>, impacts: MergeImpacts): MergeEvent => {
  const message = generateMergeMessage(instance, sourceEntities);
  const { updatedRelations, dependencyDeletions } = impacts;
  const previousStix = convertStoreToStix(previous) as StixCoreObject;
  const currentStix = convertStoreToStix(instance) as StixCoreObject;
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
      sources: R.map((s) => convertStoreToStix(s) as StixCoreObject, sourceEntities),
      deletions: R.map((s) => convertStoreToStix(s) as StixCoreObject, dependencyDeletions),
      shifts: updatedRelations,
    }
  };
};
export const storeMergeEvent = async (
  context: AuthContext,
  user: AuthUser,
  initialInstance: StoreObject,
  mergedInstance: StoreObject,
  sourceEntities: Array<StoreObject>,
  impacts: MergeImpacts,
  opts: EventOpts,
) => {
  try {
    const event = buildMergeEvent(user, initialInstance, mergedInstance, sourceEntities, impacts);
    await pushToStream(context, user, clientBase, event, opts);
    return event;
  } catch (e) {
    throw DatabaseError('Error in store merge event', { error: e });
  }
};
// Update
export const buildStixUpdateEvent = (user: AuthUser, previousStix: StixCoreObject, stix: StixCoreObject, message: string, opts: UpdateEventOpts = {}): UpdateEvent => {
  // Build and send the event
  const patch = jsonpatch.compare(previousStix, stix);
  const previousPatch = jsonpatch.compare(stix, previousStix);
  if (patch.length === 0 || previousPatch.length === 0) {
    throw UnsupportedError('Update event must contains a valid previous patch');
  }
  if (patch.length === 1 && patch[0].path === '/modified') {
    throw UnsupportedError('Update event must contains more operation than just modified/updated_at value');
  }
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_UPDATE,
    scope: 'external',
    message,
    origin: user.origin,
    data: stix,
    commit: opts.commit,
    context: {
      patch,
      reverse_patch: previousPatch
    }
  };
};
export const publishStixToStream = async (context: AuthContext, user: AuthUser, event: StreamDataEvent) => {
  await pushToStream(context, user, clientBase, event);
};
const buildUpdateEvent = (user: AuthUser, previous: StoreObject, instance: StoreObject, message: string, opts: UpdateEventOpts): UpdateEvent => {
  // Build and send the event
  const stix = convertStoreToStix(instance) as StixCoreObject;
  const previousStix = convertStoreToStix(previous) as StixCoreObject;
  return buildStixUpdateEvent(user, previousStix, stix, message, opts);
};
export const storeUpdateEvent = async (context: AuthContext, user: AuthUser, previous: StoreObject, instance: StoreObject, message: string, opts: UpdateEventOpts = {}) => {
  try {
    if (isStixExportableData(instance)) {
      const event = buildUpdateEvent(user, previous, instance, message, opts);
      await pushToStream(context, user, clientBase, event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store update event', { error: e });
  }
};
// Create
export const buildCreateEvent = (user: AuthUser, instance: StoreObject, message: string): StreamDataEvent => {
  const stix = convertStoreToStix(instance) as StixCoreObject;
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_CREATE,
    scope: 'external',
    message,
    origin: user.origin,
    data: stix,
  };
};
export const storeCreateRelationEvent = async (context: AuthContext, user: AuthUser, instance: StoreRelation, opts: CreateEventOpts = {}) => {
  try {
    if (isStixExportableData(instance)) {
      const { withoutMessage = false } = opts;
      const message = withoutMessage ? '-' : generateCreateMessage(instance);
      const event = buildCreateEvent(user, instance, message);
      await pushToStream(context, user, clientBase, event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create relation event', { error: e });
  }
};
export const storeCreateEntityEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, message: string, opts: CreateEventOpts = {}) => {
  try {
    if (isStixExportableData(instance)) {
      const event = buildCreateEvent(user, instance, message);
      await pushToStream(context, user, clientBase, event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create entity event', { error: e });
  }
};

// Delete
export const buildDeleteEvent = async (
  user: AuthUser,
  instance: StoreObject,
  message: string,
  deletions: Array<StoreObject>,
): Promise<DeleteEvent> => {
  const stix = convertStoreToStix(instance) as StixCoreObject;
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_DELETE,
    scope: 'external',
    message,
    origin: user.origin,
    data: stix,
    context: {
      deletions: R.map((s) => convertStoreToStix(s) as StixCoreObject, deletions)
    }
  };
};
export const storeDeleteEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, deletions: Array<StoreObject>, opts: EventOpts = {}) => {
  try {
    if (isStixExportableData(instance)) {
      const message = generateDeleteMessage(instance);
      const event = await buildDeleteEvent(user, instance, message, deletions);
      await pushToStream(context, user, clientBase, event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store delete event', { error: e });
  }
};
export const deleteStream = () => clientBase.call('DEL', REDIS_STREAM_NAME);

const mapStreamToJS = ([id, data]: any): SseEvent<any> => {
  const count = data.length / 2;
  const obj: any = {};
  for (let i = 0; i < count; i += 1) {
    obj[data[2 * i]] = JSON.parse(data[2 * i + 1]);
  }
  return { id, event: obj.type, data: obj };
};
export const fetchStreamInfo = async () => {
  const res: any = await clientBase.xinfo('STREAM', REDIS_STREAM_NAME);
  const info: any = R.fromPairs(R.splitEvery(2, res) as any);
  const firstId = info['first-entry'][0];
  const firstEventDate = utcDate(parseInt(firstId.split('-')[0], 10)).toISOString();
  const lastId = info['last-entry'][0];
  const lastEventDate = utcDate(parseInt(lastId.split('-')[0], 10)).toISOString();
  return { lastEventId: lastId, firstEventId: firstId, firstEventDate, lastEventDate, streamSize: info.length };
};

const processStreamResult = async (results: Array<any>, callback: any, withInternal: boolean) => {
  const streamData = R.map((r) => mapStreamToJS(r), results);
  const filteredEvents = streamData.filter((s) => {
    return withInternal ? true : (s.data.scope ?? 'external') === 'external';
  });
  const lastEventId = filteredEvents.length > 0 ? R.last(filteredEvents)?.id : `${new Date().getTime()}-0`;
  await callback(filteredEvents, lastEventId);
  return lastEventId;
};

export const STREAM_BATCH_TIME = 15000;
const MAX_RANGE_MESSAGES = 100;

export interface StreamProcessor {
  info: () => Promise<object>;
  start: (from: string | undefined) => Promise<void>;
  shutdown: () => Promise<void>;
}

interface StreamOption {
  withInternal: boolean;
  streamName: string;
}

export const createStreamProcessor = <T extends BaseEvent> (
  user: AuthUser,
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => void,
  opts: StreamOption = { withInternal: false, streamName: REDIS_STREAM_NAME }
): StreamProcessor => {
  let client: Redis;
  let startEventId: string;
  let processingLoopPromise: Promise<void>;
  let streamListening = true;
  const processInfo = async () => {
    return fetchStreamInfo();
  };
  const processStep = async () => {
    // since previous call is async (and blocking) we should check if we are still running before processing the message
    if (!streamListening) {
      return false;
    }
    try {
      // Consume the data stream
      const streamResult = await client.call(
        'XREAD',
        'COUNT',
        MAX_RANGE_MESSAGES,
        'BLOCK',
        STREAM_BATCH_TIME,
        'STREAMS',
        opts.streamName,
        startEventId
      ) as any[];
      // Process the event results
      if (streamResult && streamResult.length > 0) {
        const [, results] = streamResult[0];
        const lastElementId = await processStreamResult(results, callback, opts.withInternal);
        startEventId = lastElementId || startEventId;
      } else {
        await processStreamResult([], callback, opts.withInternal);
      }
    } catch (err) {
      logApp.error(`Error in redis streams read for ${provider}`, { error: err });
      await waitInSec(2);
    }
    return streamListening;
  };
  const processingLoop = async () => {
    while (streamListening) {
      if (!(await processStep())) {
        break;
      }
    }
  };
  return {
    info: async () => processInfo(),
    start: async (start = 'live') => {
      let fromStart = start;
      if (isEmptyField(fromStart)) {
        fromStart = 'live';
      }
      startEventId = fromStart === 'live' ? '$' : fromStart;
      logApp.info(`[STREAM] Starting stream processor at ${startEventId} for ${provider}`);
      client = await createRedisClient(provider); // Create client for this processing loop
      processingLoopPromise = processingLoop();
    },
    shutdown: async () => {
      logApp.info(`[STREAM] Shutdown stream processor for ${provider}`);
      streamListening = false;
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
      logApp.info('[STREAM] Stream processor current promise terminated');
      if (client) {
        await client.disconnect();
      }
    },
  };
};
// endregion

// region opencti notification stream
export const storeNotificationEvent = async (context: AuthContext, event: any) => {
  await clientBase.call('XADD', NOTIFICATION_STREAM_NAME, 'MAXLEN', '~', notificationTrimming, '*', ...mapJSToStream(event));
};
export const fetchRangeNotifications = async <T extends BaseEvent> (start: Date, end: Date): Promise<Array<T>> => {
  const streamResult = await clientBase.call('XRANGE', NOTIFICATION_STREAM_NAME, start.getTime(), end.getTime()) as any[];
  const streamElements: Array<SseEvent<T>> = R.map((r) => mapStreamToJS(r), streamResult);
  return streamElements.filter((s) => s.event === 'live').map((e) => e.data);
};
// endregion

// region work handling
export const redisDeleteWorks = async (internalIds: Array<string>) => {
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  return redisTx(clientBase, (tx) => {
    tx.del(...ids);
  });
};
export const redisGetWork = async (internalId: string) => {
  return clientBase.hgetall(internalId);
};
export const redisUpdateWorkFigures = async (workId: string) => {
  const timestamp = now();
  await redisTx(clientBase, async (tx) => {
    if (workId.includes('_')) { // Handle a connector status.
      const [, connectorId] = workId.split('_');
      await tx.set(`work:${connectorId}`, workId);
    }
    await updateObjectCounterRaw(tx, workId, 'import_processed_number', 1);
    await updateObjectRaw(tx, workId, { import_last_processed: timestamp });
  });
  const updatedMetrics = await redisGetWork(workId);
  const { import_processed_number: pn, import_expected_number: en }: any = updatedMetrics;
  return { isComplete: parseInt(pn, 10) === parseInt(en, 10), total: pn, expected: en };
};
export const redisGetConnectorStatus = async (connectorId: string) => {
  return clientBase.get(`work:${connectorId}`);
};
export const redisUpdateActionExpectation = async (user: AuthUser, workId: string, expectation: number) => {
  await redisTx(clientBase, async (tx) => {
    await updateObjectCounterRaw(tx, workId, 'import_expected_number', expectation);
  });
  return workId;
};
// endregion

// region cluster handling
const CLUSTER_LIST_KEY = 'platform_cluster';
const CLUSTER_NODE_EXPIRE = 120;
export const registerClusterInstance = async (instanceId: string, instanceConfig: ClusterConfig) => {
  await redisTx(clientBase, async (tx) => {
    // add (or update if it already exists) a key with a TTL
    tx.set(instanceId, JSON.stringify(instanceConfig), 'EX', CLUSTER_NODE_EXPIRE);
    // add/update the instance with its creation date in the ordered list of instances
    const time = new Date().getTime();
    tx.zadd(CLUSTER_LIST_KEY, time, instanceId);
    // remove the too old keys from the list of instances
    tx.zremrangebyscore(CLUSTER_LIST_KEY, '-inf', time - (CLUSTER_NODE_EXPIRE * 1000));
  });
};
export const getClusterInstances = async () => {
  const instances = await clientBase.zrange(CLUSTER_LIST_KEY, 0, -1);
  if (instances && instances.length > 0) {
    const instancesConfig = await clientBase.mget(...instances);
    return instancesConfig.filter(filterEmpty).map((n) => JSON.parse(n));
  }
  return [];
};
// endregion
