import { SEMATTRS_DB_NAME } from '@opentelemetry/semantic-conventions';
import Redis, { Cluster, type RedisOptions, type SentinelAddress } from 'ioredis';
import Redlock from 'redlock';
import * as jsonpatch from 'fast-json-patch';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
import type { ChainableCommander } from 'ioredis/built/utils/RedisCommander';
import type { ClusterOptions } from 'ioredis/built/cluster/ClusterOptions';
import type { SentinelConnectionOptions } from 'ioredis/built/connectors/SentinelConnector';
import conf, { booleanConf, configureCA, DEV_MODE, getStoppingState, loadCert, logApp, REDIS_PREFIX } from '../config/conf';
import {
  asyncListTransformation,
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_MERGE,
  EVENT_TYPE_UPDATE,
  isEmptyField,
  MAX_EVENT_LOOP_PROCESSING_TIME,
  waitInSec
} from './utils';
import { isStixExportableData } from '../schema/stixCoreObject';
import { DatabaseError, LockTimeoutError, UnsupportedError } from '../config/errors';
import { mergeDeepRightAll, now, utcDate } from '../utils/format';
import { convertStoreToStix } from './stix-converter';
import type { StoreObject, StoreRelation } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import type { BaseEvent, CreateEventOpts, DeleteEvent, EventOpts, MergeEvent, SseEvent, StreamDataEvent, UpdateEvent, UpdateEventOpts } from '../types/event';
import type { StixCoreObject } from '../types/stix-common';
import type { EditContext } from '../generated/graphql';
import { telemetry } from '../config/tracing';
import type { ClusterConfig } from '../manager/clusterManager';
import type { ActivityStreamEvent } from '../manager/activityListener';
import type { ExecutionEnvelop } from '../manager/playbookManager';
import { generateCreateMessage, generateDeleteMessage, generateMergeMessage, generateRestoreMessage } from './generate-message';
import { INPUT_OBJECTS } from '../schema/general';
import { enrichWithRemoteCredentials } from '../config/credentials';

const MAX_MULTI_REDIS_OPERATIONS = 50;
const USE_SSL = booleanConf('redis:use_ssl', false);
const REDIS_CA = conf.get('redis:ca').map((path: string) => loadCert(path));
export const REDIS_STREAM_NAME = `${REDIS_PREFIX}stream.opencti`;
export const EVENT_CURRENT_VERSION = '4';

const isStreamPublishable = (opts: EventOpts) => {
  return opts.publishStreamEvent === undefined || opts.publishStreamEvent;
};

const redisOptions = async (autoReconnect = false): Promise<RedisOptions> => {
  const baseAuth = { username: conf.get('redis:username'), password: conf.get('redis:password') };
  const userPasswordAuth = await enrichWithRemoteCredentials('redis', baseAuth);
  return {
    keyPrefix: REDIS_PREFIX,
    ...userPasswordAuth,
    tls: USE_SSL ? { ...configureCA(REDIS_CA), servername: conf.get('redis:hostname') } : undefined,
    retryStrategy: /* v8 ignore next */ (times) => {
      if (getStoppingState()) {
        return null;
      }
      if (autoReconnect) {
        return Math.min(times * 50, 2000);
      }
      return null;
    },
    lazyConnect: true,
    enableAutoPipelining: false,
    enableOfflineQueue: true,
    maxRetriesPerRequest: autoReconnect ? null : 1,
    showFriendlyErrorStack: DEV_MODE,
    family: conf.get('redis:host_ip_family') ?? 4,
  };
};

// From "HOST:PORT" to { host, port }
export const generateClusterNodes = (nodes: string[]): { host: string; port: number; }[] => {
  return nodes.map((h: string) => {
    const [host, port] = h.split(':');
    return { host, port: parseInt(port, 10) };
  });
};

// From "HOST:PORT>HOST:PORT" to { ["HOST:PORT"]: { host, port } }
export const generateNatMap = (mappings: string[]): Record<string, { host: string; port: number; }> => {
  const natMap: Record<string, { host: string; port: number; }> = {};
  for (let i = 0; i < mappings.length; i += 1) {
    const mapping = mappings[i];
    const [from, to] = mapping.split('>');
    const [host, port] = to.split(':');
    natMap[from] = { host, port: parseInt(port, 10) };
  }
  return natMap;
};

const clusterOptions = async (): Promise<ClusterOptions> => {
  const redisOpts = await redisOptions();
  return {
    keyPrefix: REDIS_PREFIX,
    lazyConnect: true,
    enableAutoPipelining: false,
    enableOfflineQueue: true,
    redisOptions: redisOpts,
    scaleReads: conf.get('redis:scale_reads') ?? 'all',
    natMap: generateNatMap(conf.get('redis:nat_map') ?? []),
    showFriendlyErrorStack: DEV_MODE,
  };
};

const sentinelOptions = async (clusterNodes: Partial<SentinelAddress>[]): Promise<SentinelConnectionOptions> => {
  const baseAuth = { sentinelPassword: conf.get('redis:sentinel_password') };
  const passwordAuth = await enrichWithRemoteCredentials('redis', baseAuth);
  return {
    ...passwordAuth,
    keyPrefix: REDIS_PREFIX,
    name: conf.get('redis:sentinel_master_name'),
    role: conf.get('redis:sentinel_role'),
    preferredSlaves: conf.get('redis:sentinel_preferred_slaves'),
    sentinels: clusterNodes,
    enableTLSForSentinelMode: conf.get('redis:sentinel_tls') ?? false,
    failoverDetector: conf.get('redis:sentinel_failover_detector') ?? false,
    updateSentinels: conf.get('redis:sentinel_update_sentinels') ?? true,
  };
};

export const createRedisClient = async (provider: string, autoReconnect = false): Promise<Cluster | Redis> => {
  let client: Cluster | Redis;
  const redisMode: string = conf.get('redis:mode');
  const clusterNodes = generateClusterNodes(conf.get('redis:hostnames') ?? []);
  if (redisMode === 'cluster') {
    const clusterOpts = await clusterOptions();
    client = new Redis.Cluster(clusterNodes, clusterOpts);
  } else if (redisMode === 'sentinel') {
    const sentinelOpts = await sentinelOptions(clusterNodes);
    client = new Redis(sentinelOpts);
  } else {
    const singleOptions = await redisOptions(autoReconnect);
    client = new Redis({ ...singleOptions, db: conf.get('redis:database') ?? 0, port: conf.get('redis:port'), host: conf.get('redis:hostname') });
  }

  client.on('close', () => logApp.info(`[REDIS] Redis '${provider}' client closed`));
  client.on('ready', () => logApp.info(`[REDIS] Redis '${provider}' client ready`));
  client.on('error', (err) => logApp.error(DatabaseError('Redis client connection fail', { cause: err, provider })));
  client.on('reconnecting', () => logApp.info(`[REDIS] '${provider}' Redis client reconnecting`));
  return client;
};

// region Initialization of clients
type RedisConnection = Cluster | Redis ;
interface RedisClients { base: RedisConnection, lock: RedisConnection, pubsub: RedisPubSub }

let redisClients: RedisClients;
export const initializeRedisClients = async () => {
  const base = await createRedisClient('base', true);
  const lock = await createRedisClient('lock', true);
  const publisher = await createRedisClient('publisher', true);
  const subscriber = await createRedisClient('subscriber', true);
  redisClients = {
    base,
    lock,
    pubsub: new RedisPubSub({
      publisher,
      subscriber,
      connectionListener: (err) => {
        logApp.info('[REDIS] Redis pubsub client closed', { error: err });
      }
    })
  };
};
export const shutdownRedisClients = async () => {
  await redisClients.base?.quit().catch(() => { /* Dont care */ });
  await redisClients.lock?.quit().catch(() => { /* Dont care */ });
  await redisClients.pubsub?.close().catch(() => { /* Dont care */ });
};
// endregion

// region pubsub
const getClientBase = (): Cluster | Redis => redisClients.base;
const getClientLock = (): Cluster | Redis => redisClients.lock;
const getClientPubSub = (): RedisPubSub => redisClients.pubsub;
export const pubSubAsyncIterator = (topic: string | string[]) => {
  return getClientPubSub().asyncIterator(topic);
};
export const pubSubSubscription = async <T>(topic: string, onMessage: (message: T) => void) => {
  const subscription = await getClientPubSub().subscribe(topic, onMessage, { pattern: true });
  const unsubscribe = () => getClientPubSub().unsubscribe(subscription);
  return { topic, unsubscribe };
};
// endregion

// region basic operations
export const redisTx = async (client: Cluster | Redis, chain: (tx: ChainableCommander) => Promise<void>) => {
  const tx = client.multi();
  try {
    await chain(tx);
    return await tx.exec();
  } catch (e) {
    throw DatabaseError('Redis transaction error', { cause: e });
  }
};
const updateObjectRaw = async (tx: ChainableCommander, id: string, input: object) => {
  const data = R.flatten(R.toPairs(input));
  tx.hset(id, data);
};
const updateObjectCounterRaw = async (tx: ChainableCommander, id: string, field: string, number: number) => {
  tx.hincrby(id, field, number);
};
const setInList = async (listId: string, keyId: string, expirationTime: number) => {
  await redisTx(getClientBase(), async (tx) => {
    // add/update the instance with its creation date in the ordered list of instances
    const time = new Date().getTime();
    tx.zadd(listId, time, keyId);
    // remove the too old keys from the list of instances
    tx.zremrangebyscore(listId, '-inf', time - (expirationTime * 1000));
  });
};
const delKeyWithList = async (baseKeyId: string, listId: string) => {
  const keyId = `{${listId}}:${baseKeyId}`; // Key of a list must be attached to the same redis slot
  const keyPromise = getClientBase().del(keyId);
  const listsPromise = getClientBase().zrem(listId, keyId);
  await Promise.all([keyPromise, listsPromise]);
};
const setKeyWithList = async (baseKeyId: string, listId: string, keyData: any, expirationTime: number) => {
  const keyId = `{${listId}}:${baseKeyId}`; // Key of a list must be attached to the same redis slot
  const keyPromise = getClientBase().set(keyId, JSON.stringify(keyData), 'EX', expirationTime);
  const listsPromise = setInList(listId, keyId, expirationTime);
  await Promise.all([keyPromise, listsPromise]);
  return keyData;
};
const keysFromList = async (listId: string, expirationTime?: number) => {
  if (expirationTime) {
    const time = new Date().getTime();
    await getClientBase().zremrangebyscore(listId, '-inf', time - (expirationTime * 1000));
  }
  const instanceKeys = await getClientBase().zrange(listId, 0, -1);
  if (instanceKeys && instanceKeys.length > 0) {
    const keysElements = [];
    const keysBulk = R.splitEvery(MAX_MULTI_REDIS_OPERATIONS, instanceKeys);
    for (let ind = 0; ind < keysBulk.length; ind += 1) {
      const partInstances = keysBulk[ind];
      let startProcessingTime = new Date().getTime();
      const sessions = await redisTx(getClientBase(), async (tx) => {
        for (let index = 0; index < partInstances.length; index += 1) {
          const key = partInstances[index];
          tx.get(key).ttl(key);
          if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
            startProcessingTime = new Date().getTime();
            await new Promise((resolve) => {
              setImmediate(resolve);
            });
          }
        }
      }) ?? [];
      startProcessingTime = new Date().getTime();
      for (let n = 0; n < sessions.length; n += 2) {
        const cookie = sessions[n][1] as string;
        if (cookie) {
          const ttl = sessions[n + 1][1];
          const id = partInstances[n / 2];
          keysElements.push({ redis_key_id: id, redis_key_ttl: ttl, ...JSON.parse(cookie) });
        }
        if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
          startProcessingTime = new Date().getTime();
          await new Promise((resolve) => {
            setImmediate(resolve);
          });
        }
      }
    }
    return keysElements;
  }
  return [];
};
// endregion

// region session
const PLATFORM_KEY_SESSIONS = 'platform_sessions';
export const clearSessions = async () => {
  const instanceKeys = await getClientBase().zrange(PLATFORM_KEY_SESSIONS, 0, -1);
  if (instanceKeys && instanceKeys.length > 0) {
    const keysBulk = R.splitEvery(MAX_MULTI_REDIS_OPERATIONS, instanceKeys);
    for (let ind = 0; ind < keysBulk.length; ind += 1) {
      const partInstances = keysBulk[ind];
      await redisTx(getClientBase(), async (tx) => {
        let startProcessingTime = new Date().getTime();
        for (let index = 0; index < partInstances.length; index += 1) {
          const key = partInstances[index];
          tx.del(key);
          if (new Date().getTime() - startProcessingTime > MAX_EVENT_LOOP_PROCESSING_TIME) {
            startProcessingTime = new Date().getTime();
            await new Promise((resolve) => {
              setImmediate(resolve);
            });
          }
        }
      });
    }
  }
  await getClientBase().del(PLATFORM_KEY_SESSIONS);
  return true;
};
export const getSession = async (baseKeyId: string) => {
  const key = `{${PLATFORM_KEY_SESSIONS}}:${baseKeyId}`; // Key of a list must be attached to the same redis slot
  const sessionInformation = await redisTx(getClientBase(), async (tx) => {
    tx.get(key).ttl(key);
  });
  const session = sessionInformation?.at(0)?.at(1);
  if (session) {
    const ttl = Number(sessionInformation?.at(1)?.at(1));
    return { ...JSON.parse(String(session)), expiration: ttl };
  }
  return undefined;
};
export const getSessionTtl = (baseKeyId: string) => {
  const key = `{${PLATFORM_KEY_SESSIONS}}:${baseKeyId}`; // Key of a list must be attached to the same redis slot
  return getClientBase().ttl(key);
};
export const setSession = (key: string, value: any, expirationTime: number) => {
  return setKeyWithList(key, PLATFORM_KEY_SESSIONS, value, expirationTime);
};
export const killSession = async (baseKeyId: string) => {
  const key = `{${PLATFORM_KEY_SESSIONS}}:${baseKeyId}`; // Key of a list must be attached to the same redis slot
  const currentSession = await getSession(key);
  await delKeyWithList(key, PLATFORM_KEY_SESSIONS);
  return { sessionId: key, session: currentSession };
};
export const getSessionKeys = () => {
  return getClientBase().zrange(PLATFORM_KEY_SESSIONS, 0, -1);
};
export const getSessions = () => {
  return keysFromList(PLATFORM_KEY_SESSIONS);
};
export const extendSession = async (sessionId: string, extension: number) => {
  const sessionExtensionPromise = getClientBase().expire(sessionId, extension);
  const refreshListPromise = setInList(PLATFORM_KEY_SESSIONS, sessionId, extension);
  const [sessionExtension] = await Promise.all([sessionExtensionPromise, refreshListPromise]);
  return sessionExtension;
};
// endregion
export const redisIsAlive = async () => {
  try {
    await getClientBase().get('test-key');
    return true;
  } catch {
    throw DatabaseError('Redis seems down');
  }
};
export const redisInit = async () => {
  try {
    await initializeRedisClients();
    await redisIsAlive();
    const redisMode: string = conf.get('redis:mode');
    logApp.info(`[REDIS] Clients initialized in ${redisMode} mode`);
    return true;
  } catch {
    throw DatabaseError('Redis seems down');
  }
};
export const getRedisVersion = async () => {
  const serverInfo = await getClientBase().call('INFO') as string;
  const versionString = serverInfo.split('\r\n')[1];
  return versionString.split(':')[1];
};

/* v8 ignore next */
export const notify = async (topic: string, instance: any, user: AuthUser) => {
  // Instance can be empty if user is currently looking for a deleted instance
  if (instance) {
    // Resolved object_refs must be dissoc from original objects as not directly used for live update
    // and can imply very large event message
    const data = R.dissoc(INPUT_OBJECTS, instance);
    await getClientPubSub().publish(topic, { instance: data, user });
  }
  return instance;
};

// region user context (clientContext)
const FIVE_MINUTES = 5 * 60;
export const setEditContext = async (user: AuthUser, instanceId: string, input: EditContext) => {
  const data = R.assoc('name', user.user_email, input);
  await setKeyWithList(`edit:${instanceId}:${user.id}`, `context:instance:${instanceId}`, data, FIVE_MINUTES);
};
export const fetchEditContext = async (instanceId: string) => {
  return keysFromList(`context:instance:${instanceId}`, FIVE_MINUTES);
};
export const delEditContext = async (user: AuthUser, instanceId: string) => {
  return delKeyWithList(`edit:${instanceId}:${user.id}`, `context:instance:${instanceId}`);
};
// endregion

// region locking (clientContext)
export const redisAddDeletions = async (internalIds: Array<string>) => {
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  await redisTx(getClientLock(), async (tx) => {
    const time = new Date().getTime();
    // remove the too old keys from the list of instances
    await tx.zremrangebyscore('platform-deletions', '-inf', time - (5 * 1000));
    // add/update the instance with its creation date in the ordered list of instances
    await tx.zadd('platform-deletions', time, ...ids);
  });
};
export const redisFetchLatestDeletions = async () => {
  const time = new Date().getTime();
  await getClientLock().zremrangebyscore('platform-deletions', '-inf', time - (5 * 1000));
  return getClientLock().zrange('platform-deletions', 0, -1);
};
interface LockOptions { automaticExtension?: boolean, retryCount?: number }
const defaultLockOpts: LockOptions = { automaticExtension: true, retryCount: conf.get('app:concurrency:retry_count') };
const getStackTrace = () => {
  const obj: any = {};
  Error.captureStackTrace(obj, getStackTrace);
  return obj.stack;
};
export const lockResource = async (resources: Array<string>, opts: LockOptions = defaultLockOpts) => {
  let timeout: NodeJS.Timeout | undefined;
  let extension: undefined | Promise<void>;
  const initialCallStack = getStackTrace();
  const locks = R.uniq(resources).map((id) => `{locks}:${id}`);
  const automaticExtensionThreshold = conf.get('app:concurrency:extension_threshold');
  const retryDelay = conf.get('app:concurrency:retry_delay');
  const retryJitter = conf.get('app:concurrency:retry_jitter');
  const maxTtl = conf.get('app:concurrency:max_ttl');
  const controller = new AbortController();
  const { signal } = controller;
  const autoExtension = opts.automaticExtension ? opts.automaticExtension : true;
  const redlock = new Redlock([getClientLock()], { retryCount: opts.retryCount, retryDelay, retryJitter });
  // Get the lock
  let lock = await redlock.acquire(locks, maxTtl); // Force unlock after maxTtl
  const queue = () => {
    timeout = setTimeout(
      () => {
        // eslint-disable-next-line @typescript-eslint/no-use-before-define
        extension = extend();
      },
      lock.expiration - Date.now() - 2 * automaticExtensionThreshold
    );
  };
  const extend = async () => {
    try {
      if (opts.retryCount !== 0) {
        logApp.warn('Extending resources for long processing task', { locks, stack: initialCallStack });
      }
      lock = await lock.extend(maxTtl);
      queue();
    } catch (error) {
      controller.abort('[REDIS] Failed to extend resource');
    }
  };
  // If lock succeed we need to be sure that delete not occurred just before the resolution/lock
  // If we do not check for that, we could update an entity even though it was just deleted, resulting in the entity being created again
  const latestDeletions = await redisFetchLatestDeletions();
  const deletedParticipantsIds = resources.filter((x) => latestDeletions.includes(x));
  if (deletedParticipantsIds.length > 0) {
    // noinspection ExceptionCaughtLocallyJS
    await lock.release();
    throw LockTimeoutError({ participantIds: deletedParticipantsIds });
  }
  // If everything seems good, start auto extension if needed
  if (autoExtension) {
    queue();
  }
  // Return the lock and capable actions
  return {
    signal,
    extend,
    unlock: async () => {
      // First, wait for an in-flight extension to finish.
      if (extension) {
        await extension.catch(() => {
          // An error here doesn't matter at all, because the routine has
          // already completed, and a release will be attempted regardless. The
          // only reason for waiting here is to prevent possible contention
          // between the extension and release.
        });
      }
      // Second, clear the auto extends possibly starts by the first step
      clearTimeout(timeout);
      // Last, unlock in redis
      try {
        // Finally try to unlock
        await lock.release();
      } catch (e) {
        // Nothing to do here
        logApp.warn('Failed to unlock resource', { locks });
      }
    },
  };
};
// endregion

// region opencti data stream
const streamTrimming = conf.get('redis:trimming') || 0;
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
const pushToStream = async (context: AuthContext, user: AuthUser, client: Cluster | Redis, event: BaseEvent, opts: EventOpts = {}) => {
  if (isStreamPublishable(opts)) {
    const pushToStreamFn = async () => {
      if (streamTrimming) {
        await client.call('XADD', REDIS_STREAM_NAME, 'MAXLEN', '~', streamTrimming, '*', ...mapJSToStream(event));
      } else {
        await client.call('XADD', REDIS_STREAM_NAME, '*', ...mapJSToStream(event));
      }
    };
    telemetry(context, user, 'INSERT STREAM', {
      [SEMATTRS_DB_NAME]: 'stream_engine',
    }, pushToStreamFn);
  }
};

// Merge
const buildMergeEvent = async (user: AuthUser, previous: StoreObject, instance: StoreObject, sourceEntities: Array<StoreObject>): Promise<MergeEvent> => {
  const message = generateMergeMessage(instance, sourceEntities);
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
      sources: await asyncListTransformation(sourceEntities, convertStoreToStix),
    }
  };
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
    await pushToStream(context, user, getClientBase(), event, opts);
    return event;
  } catch (e) {
    throw DatabaseError('Error in store merge event', { cause: e });
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
  await pushToStream(context, user, getClientBase(), event);
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
      await pushToStream(context, user, getClientBase(), event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store update event', { cause: e });
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
      const { withoutMessage = false, restore = false } = opts;
      let message = '-';
      if (!withoutMessage) {
        message = restore ? generateRestoreMessage(instance) : generateCreateMessage(instance);
      }
      const event = buildCreateEvent(user, instance, message);
      await pushToStream(context, user, getClientBase(), event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create relation event', { cause: e });
  }
};
export const storeCreateEntityEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, message: string, opts: CreateEventOpts = {}) => {
  try {
    if (isStixExportableData(instance)) {
      const event = buildCreateEvent(user, instance, message);
      await pushToStream(context, user, getClientBase(), event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store create entity event', { cause: e });
  }
};

// Delete
export const buildDeleteEvent = async (
  user: AuthUser,
  instance: StoreObject,
  message: string,
): Promise<DeleteEvent> => {
  const stix = convertStoreToStix(instance) as StixCoreObject;
  return {
    version: EVENT_CURRENT_VERSION,
    type: EVENT_TYPE_DELETE,
    scope: 'external',
    message,
    origin: user.origin,
    data: stix
  };
};
export const storeDeleteEvent = async (context: AuthContext, user: AuthUser, instance: StoreObject, opts: EventOpts = {}) => {
  try {
    if (isStixExportableData(instance)) {
      const message = generateDeleteMessage(instance);
      const event = await buildDeleteEvent(user, instance, message);
      await pushToStream(context, user, getClientBase(), event, opts);
      return event;
    }
    return undefined;
  } catch (e) {
    throw DatabaseError('Error in store delete event', { cause: e });
  }
};

const mapStreamToJS = ([id, data]: any): SseEvent<any> => {
  const count = data.length / 2;
  const obj: any = {};
  for (let i = 0; i < count; i += 1) {
    obj[data[2 * i]] = JSON.parse(data[2 * i + 1]);
  }
  return { id, event: obj.type, data: obj };
};
export const fetchStreamInfo = async () => {
  const res: any = await getClientBase().xinfo('STREAM', REDIS_STREAM_NAME);
  const info: any = R.fromPairs(R.splitEvery(2, res) as any);
  const firstId = info['first-entry'][0];
  const firstEventDate = utcDate(parseInt(firstId.split('-')[0], 10)).toISOString();
  const lastId = info['last-entry'][0];
  const lastEventDate = utcDate(parseInt(lastId.split('-')[0], 10)).toISOString();
  return { lastEventId: lastId, firstEventId: firstId, firstEventDate, lastEventDate, streamSize: info.length };
};

const processStreamResult = async (results: Array<any>, callback: any, withInternal: boolean | undefined) => {
  const streamData = R.map((r) => mapStreamToJS(r), results);
  const filteredEvents = streamData.filter((s) => {
    return withInternal ? true : (s.data.scope ?? 'external') === 'external';
  });
  const lastEventId = filteredEvents.length > 0 ? R.last(filteredEvents)?.id : `${new Date().valueOf()}-0`;
  await callback(filteredEvents, lastEventId);
  return lastEventId;
};

const STREAM_BATCH_TIME = 5000;
const MAX_RANGE_MESSAGES = 100;

export interface StreamProcessor {
  info: () => Promise<object>;
  start: (from: string | undefined) => Promise<void>;
  shutdown: () => Promise<void>;
  running: () => boolean;
}

interface StreamOption {
  withInternal?: boolean;
  autoReconnect?: boolean;
  streamName?: string;
}

export const createStreamProcessor = <T extends BaseEvent> (
  user: AuthUser,
  provider: string,
  callback: (events: Array<SseEvent<T>>, lastEventId: string) => void,
  opts: StreamOption = {}
): StreamProcessor => {
  let client: Cluster | Redis;
  let startEventId: string;
  let processingLoopPromise: Promise<void>;
  let streamListening = true;
  const streamName = opts.streamName ?? REDIS_STREAM_NAME;
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
        streamName,
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
      logApp.error(DatabaseError('Redis stream consume fail', { cause: err, provider }));
      if (opts.autoReconnect) {
        await waitInSec(2);
      } else {
        return false;
      }
    }
    return streamListening;
  };
  const processingLoop = async () => {
    while (streamListening) {
      if (!(await processStep())) {
        streamListening = false;
        break;
      }
    }
  };
  return {
    info: async () => processInfo(),
    running: () => streamListening,
    start: async (start = 'live') => {
      let fromStart = start;
      if (isEmptyField(fromStart)) {
        fromStart = 'live';
      }
      startEventId = fromStart === 'live' ? '$' : fromStart;
      logApp.info(`[STREAM] Starting stream processor at ${startEventId} for ${provider}`);
      client = await createRedisClient(provider, opts.autoReconnect); // Create client for this processing loop
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
export const NOTIFICATION_STREAM_NAME = `${REDIS_PREFIX}stream.notification`;
const notificationTrimming = conf.get('redis:notification_trimming') || 50000;
export const storeNotificationEvent = async (context: AuthContext, event: any) => {
  await getClientBase().call('XADD', NOTIFICATION_STREAM_NAME, 'MAXLEN', '~', notificationTrimming, '*', ...mapJSToStream(event));
};
export const fetchRangeNotifications = async <T extends BaseEvent> (start: Date, end: Date): Promise<Array<T>> => {
  const streamResult = await getClientBase().call('XRANGE', NOTIFICATION_STREAM_NAME, start.getTime(), end.getTime()) as any[];
  const streamElements: Array<SseEvent<T>> = R.map((r) => mapStreamToJS(r), streamResult);
  return streamElements.filter((s) => s.event === 'live').map((e) => e.data);
};
// endregion

// region opencti audit stream
export const EVENT_ACTIVITY_VERSION = '1';
export const ACTIVITY_STREAM_NAME = `${REDIS_PREFIX}stream.activity`;
const auditTrimming = conf.get('redis:activity_trimming') || 50000;
export const storeActivityEvent = async (event: ActivityStreamEvent) => {
  await getClientBase().call('XADD', ACTIVITY_STREAM_NAME, 'MAXLEN', '~', auditTrimming, '*', ...mapJSToStream(event));
};
// endregion

// region work handling
export const redisDeleteWorks = async (internalIds: Array<string>) => {
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  return Promise.all(ids.map((id) => getClientBase().del(id)));
};
export const redisGetWork = async (internalId: string) => {
  return getClientBase().hgetall(internalId);
};
export const isWorkCompleted = async (workId: string) => {
  const { import_processed_number: pn, import_expected_number: en } = await redisGetWork(workId);
  const total = parseInt(pn, 10);
  const expected = parseInt(en, 10);
  return { isComplete: total === expected, total, expected };
};
export const redisUpdateWorkFigures = async (workId: string) => {
  const timestamp = now();
  const clientBase = getClientBase();
  if (workId.includes('_')) { // Handle a connector status.
    const [, connectorId] = workId.split('_');
    await clientBase.set(`work:${connectorId}`, workId);
  }
  await redisTx(clientBase, async (tx) => {
    await updateObjectCounterRaw(tx, workId, 'import_processed_number', 1);
    await updateObjectRaw(tx, workId, { import_last_processed: timestamp });
  });
  return isWorkCompleted(workId);
};
export const redisGetConnectorStatus = async (connectorId: string) => {
  return getClientBase().get(`work:${connectorId}`);
};
export const redisUpdateActionExpectation = async (user: AuthUser, workId: string, expectation: number) => {
  await redisTx(getClientBase(), async (tx) => {
    await updateObjectCounterRaw(tx, workId, 'import_expected_number', expectation);
  });
  return workId;
};
// endregion

// region cluster handling
const CLUSTER_LIST_KEY = 'platform_cluster';
const CLUSTER_NODE_EXPIRE = 2 * 60; // 2 minutes
export const registerClusterInstance = async (instanceId: string, instanceConfig: ClusterConfig) => {
  return setKeyWithList(instanceId, CLUSTER_LIST_KEY, instanceConfig, CLUSTER_NODE_EXPIRE);
};
export const getClusterInstances = async () => {
  return keysFromList(CLUSTER_LIST_KEY, CLUSTER_NODE_EXPIRE);
};
// endregion

// playground handling
export const redisPlaybookUpdate = async (envelop: ExecutionEnvelop) => {
  const clientBase = getClientBase();
  const id = `playbook_execution_${envelop.playbook_execution_id}`;
  const follow = await clientBase.get(id);
  const objectFollow = follow ? JSON.parse(follow) : {};
  const toUpdate = mergeDeepRightAll(objectFollow, envelop);
  await setKeyWithList(id, `playbook_executions_${envelop.playbook_id}`, toUpdate, 5 * 60); // 5 minutes
};
export const getLastPlaybookExecutions = async (playbookId: string) => {
  const executions = await keysFromList(`playbook_executions_${playbookId}`, 5 * 60) as ExecutionEnvelop[];
  return executions.map((e) => {
    const steps = Object.entries(e).filter(([k, _]) => k.startsWith('step_')).map(([k, v]) => {
      const bundle_or_patch = v.bundle ? JSON.stringify([v.bundle], null, 2) : JSON.stringify(v.patch, null, 2);
      // beware, step key is the same for every execution, and we need to avoid id collision in Relay
      const id = `${e.playbook_execution_id}-${k.split('step_')[1]}`;
      return ({ id, bundle_or_patch, ...v });
    });
    return {
      id: e.playbook_execution_id,
      playbook_id: e.playbook_id,
      execution_start: steps[0].in_timestamp,
      steps
    };
  });
};
// endregion

// region - support package handling
export const SUPPORT_NODE_STATUS_IN_PROGRESS = 0;
export const SUPPORT_NODE_STATUS_READY = 10;
export const SUPPORT_NODE_STATUS_IN_ERROR = 100;

/**
 * Add or update for a given support package, one node status.
 * @param supportPackageId
 * @param nodeId
 * @param nodeStatus one of SUPPORT_NODE_STATUS_IN_PROGRESS, SUPPORT_NODE_STATUS_READY, SUPPORT_NODE_STATUS_IN_ERROR
 */
export const redisStoreSupportPackageNodeStatus = (supportPackageId:string, nodeId: string, nodeStatus: number) => {
  const setKeyId = `support:${supportPackageId}`;
  // redis score =  nodeStatus
  // redis member = nodeId
  return getClientBase().zadd(setKeyId, nodeStatus, nodeId);
};

/**
 * Count for a support package the number of node with a status.
 * @param supportPackageId
 * @param nodeStatus
 */
export const redisCountSupportPackageNodeWithStatus = (supportPackageId: string, nodeStatus: number) => {
  const setKeyId = `support:${supportPackageId}`;
  return getClientBase().zcount(setKeyId, nodeStatus, nodeStatus);
};

export const redisDeleteSupportPackageNodeStatus = (supportPackageId: string) => {
  const setKeyId = `support:${supportPackageId}`;
  return getClientBase().del(setKeyId);
};

// endregion - support package handling
