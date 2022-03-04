import { readFileSync } from 'node:fs';
import Redis from 'ioredis';
import Redlock from 'redlock';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
import { create as createJsonDiff } from 'jsondiffpatch';
import conf, { booleanConf, configureCA, DEV_MODE, ENABLED_CACHING, logApp } from '../config/conf';
import {
  generateCreateMessage,
  generateDeleteMessage,
  generateMergeMessage,
  generateUpdateMessage,
  isEmptyField,
  isInferredIndex,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
} from './utils';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from './rabbitmq';
import { convertInstanceToStix, updateInputsToPatch } from './stix';
import { DatabaseError, FunctionalError, UnsupportedError } from '../config/errors';
import { now, utcDate } from '../utils/format';
import RedisStore from './sessionStore-redis';
import SessionStoreMemory from './sessionStore-memory';
import { RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';
import { getInstanceIdentifiers, getInstanceIds } from '../schema/identifier';
import { BASE_TYPE_RELATION } from '../schema/general';
import {
  isSingleStixEmbeddedRelationship,
  isStixEmbeddedRelationship,
  STIX_EMBEDDED_RELATION_TO_FIELD,
} from '../schema/stixEmbeddedRelationship';

const USE_SSL = booleanConf('redis:use_ssl', false);
const INCLUDE_INFERENCES = booleanConf('redis:include_inferences', false);
const REDIS_CA = conf.get('redis:ca').map((path) => readFileSync(path));
const REDIS_PREFIX = conf.get('redis:namespace') ? `${conf.get('redis:namespace')}:` : '';
const REDIS_STREAM_NAME = `${REDIS_PREFIX}stream.opencti`;

const BASE_DATABASE = 0; // works key for tracking / stream
const CONTEXT_DATABASE = 1; // locks / user context
const REDIS_EXPIRE_TIME = 90;

const mustBeIncludeInStream = (instance) => {
  return INCLUDE_INFERENCES || !isInferredIndex(instance._index);
};

const redisOptions = (database) => ({
  keyPrefix: REDIS_PREFIX,
  db: database,
  port: conf.get('redis:port'),
  host: conf.get('redis:hostname'),
  username: conf.get('redis:username'),
  password: conf.get('redis:password'),
  tls: USE_SSL ? configureCA(REDIS_CA) : null,
  retryStrategy: /* istanbul ignore next */ (times) => Math.min(times * 50, 2000),
  lazyConnect: true,
  enableAutoPipelining: false,
  enableOfflineQueue: true,
  maxRetriesPerRequest: 30,
  showFriendlyErrorStack: DEV_MODE,
});

export const pubsub = new RedisPubSub({
  publisher: new Redis(redisOptions()),
  subscriber: new Redis(redisOptions()),
});
const createRedisClient = (provider, database = BASE_DATABASE) => {
  const client = new Redis(redisOptions(database));
  client.on('close', () => logApp.info(`[REDIS] Redis '${provider}' client closed`));
  client.on('ready', () => logApp.info(`[REDIS] Redis '${provider}' client ready`));
  client.on('reconnecting', () => logApp.info(`[REDIS] '${provider}' Redis client reconnecting`));
  client.defineCommand('cacheGet', {
    lua:
      'local index = 1\n'
      + "local resolvedKeys = redis.call('mget', unpack(KEYS))\n"
      + 'for p, k in pairs(resolvedKeys) do \n'
      + '    if (k==nil or (type(k) == "boolean" and not k)) then \n'
      + '        index = index+1\n'
      + '    elseif (k:sub(0, 1) == "@") then \n'
      + '        local subKey = "cache:" .. k:sub(2, #k)\n'
      + "        resolvedKeys[index] = redis.call('get', subKey)\n"
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
    await clientBase.get('test-key');
  } catch {
    throw DatabaseError('Redis seems down');
  }
  return true;
};
export const getRedisVersion = async () => {
  await clientBase.call('INFO');
  return clientBase.serverInfo.redis_version;
};

/* istanbul ignore next */
export const notify = (topic, instance, user, context) => {
  pubsub.publish(topic, { instance, user, context });
  return instance;
};

// region user context (clientContext)
const contextFetchMatch = async (match) => {
  return new Promise((resolve, reject) => {
    const elementsPromise = [];
    const stream = clientContext.scanStream({
      match,
      count: 100,
    });
    stream.on('data', (resultKeys) => {
      for (let i = 0; i < resultKeys.length; i += 1) {
        const resultKey = resultKeys[i];
        elementsPromise.push(clientContext.get(resultKey).then((d) => ({ key: resultKey, value: d })));
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
export const setEditContext = async (user, instanceId, input) => {
  const data = R.assoc('name', user.user_email, input);
  return clientContext.set(
    `edit:${instanceId}:${user.id}`,
    JSON.stringify(data),
    'ex',
    5 * 60 // Key will be remove if user is not active during 5 minutes
  );
};
export const fetchEditContext = async (instanceId) => {
  return contextFetchMatch(`edit:${instanceId}:*`);
};
export const delEditContext = async (user, instanceId) => {
  return clientContext.del(`edit:${instanceId}:${user.id}`);
};
export const delUserContext = async (user) => {
  return new Promise((resolve, reject) => {
    const stream = clientContext.scanStream({
      match: `*:*:${user.id}`,
      count: 100,
    });
    const keys = [];
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
        clientContext.del(keys);
      }
      resolve();
    });
  });
};
// endregion

// region basic operations
export const redisTx = async (client, callback) => {
  const tx = client.multi();
  try {
    await callback(tx);
    return tx.exec();
  } catch (e) {
    throw DatabaseError('Redis Tx error', { error: e });
  }
};
export const updateObjectRaw = async (tx, id, input) => {
  const data = R.flatten(R.toPairs(input));
  await tx.hset(id, data);
};
export const updateObjectCounterRaw = async (tx, id, field, number) => {
  await tx.hincrby(id, field, number);
};
// endregion

// region concurrent deletion
export const redisAddDeletions = async (internalIds) => {
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
const checkParticipantsDeletion = async (participantIds) => {
  const latestDeletions = await redisFetchLatestDeletions();
  const deletedParticipantsIds = participantIds.filter((x) => latestDeletions.includes(x));
  if (deletedParticipantsIds.length > 0) {
    // noinspection ExceptionCaughtLocallyJS
    throw FunctionalError('Cant update an element based on deleted dependencies', { deletedParticipantsIds });
  }
};
export const lockResource = async (resources, automaticExtension = true) => {
  let timeout;
  const locks = R.uniq(resources);
  const automaticExtensionThreshold = conf.get('app:concurrency:extension_threshold');
  const retryCount = conf.get('app:concurrency:retry_count');
  const retryDelay = conf.get('app:concurrency:retry_delay');
  const retryJitter = conf.get('app:concurrency:retry_jitter');
  const maxTtl = conf.get('app:concurrency:max_ttl');
  const redlock = new Redlock([clientContext], { retryCount, retryDelay, retryJitter });
  // Get the lock
  const lock = await redlock.lock(locks, maxTtl); // Force unlock after maxTtl
  let expiration = Date.now() + maxTtl;
  const extend = async () => {
    try {
      await lock.extend(maxTtl);
      expiration = Date.now() + maxTtl;
      if (automaticExtension) {
        // eslint-disable-next-line no-use-before-define
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
        await lock.unlock();
      } catch (e) {
        logApp.debug('[REDIS] Failed to unlock resource', { locks });
      }
    },
  };
};
// endregion

// region cache
const cacheExtraIds = (e) => getInstanceIds(e, true).map((i) => `cache:${i}`);
export const cacheSet = async (elements) => {
  if (ENABLED_CACHING) {
    await redisTx(clientCache, (tx) => {
      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        tx.set(`cache:${element.internal_id}`, JSON.stringify(element), 'ex', 5 * 60);
        const ids = cacheExtraIds(element);
        for (let indexId = 0; indexId < ids.length; indexId += 1) {
          const id = ids[indexId];
          tx.set(id, `@${element.internal_id}`, 'ex', 5 * 60);
        }
      }
    });
  }
};
export const cacheDel = async (elements) => {
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
export const cacheGet = async (id) => {
  const ids = Array.isArray(id) ? id : [id];
  if (ENABLED_CACHING) {
    const result = {};
    if (ids.length > 0) {
      const keyValues = await clientCache.cacheGet(
        ids.length,
        ids.map((i) => `cache:${i}`)
      );
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

// region opencti stream
const streamTrimming = conf.get('redis:trimming') || 0;
const mapJSToStream = (event) => {
  const cmdArgs = [];
  Object.keys(event).forEach((key) => {
    const value = event[key];
    if (value !== undefined) {
      cmdArgs.push(key);
      cmdArgs.push(JSON.stringify(value));
    }
  });
  return cmdArgs;
};
export const buildEvent = (eventType, user, markings, message, data, commitMessage = undefined, references = []) => {
  if (!data.id || !data.x_opencti_id || !data.type) {
    throw UnsupportedError('Stream event requires id, type and x_opencti_id');
  }
  return {
    version: '3', // Event version.
    type: eventType,
    origin: user.origin,
    markings: markings || [],
    message,
    commit: {
      message: commitMessage,
      references,
    },
    data,
  };
};
const pushToStream = (client, event) => {
  // Event can be empty because of UUIDv1 in STIX IDs
  if (!event) {
    return true;
  }
  if (streamTrimming) {
    return client.call('XADD', REDIS_STREAM_NAME, 'MAXLEN', '~', streamTrimming, '*', ...mapJSToStream(event));
  }
  return client.call('XADD', REDIS_STREAM_NAME, '*', ...mapJSToStream(event));
};

const DIFF_ADDED = 1;
const DIFF_CHANGE = 2;
const DIFF_REMOVE = 3;
const DIFF_TYPE = '_t';
const DIFF_TYPE_ARRAY = 'a';
export const computeMergeDifferential = (initialInstance, mergedInstance) => {
  const convertInit = convertInstanceToStix(initialInstance, { patchGeneration: true });
  const convertMerged = convertInstanceToStix(mergedInstance, { patchGeneration: true });
  const diffGenerator = createJsonDiff({
    objectHash: (obj) => {
      return obj.x_opencti_id;
    },
  });
  const patch = {};
  const diff = diffGenerator.diff(convertInit, convertMerged);
  if (diff) {
    // Result of the merge could be the exact same instance
    const entries = Object.entries(diff);
    for (let index = 0; index < entries.length; index += 1) {
      const [field, diffDelta] = entries[index];
      // https://github.com/benjamine/jsondiffpatch/blob/master/docs/deltas.md
      if (Array.isArray(diffDelta)) {
        let current;
        let previous;
        // Value added
        if (diffDelta.length === DIFF_ADDED) {
          const value = R.head(diffDelta);
          current = value;
          previous = Array.isArray(value) ? [] : '';
        }
        // Value changed
        if (diffDelta.length === DIFF_CHANGE) {
          current = R.last(diffDelta);
          previous = R.head(diffDelta);
        }
        // Value removed
        if (diffDelta.length === DIFF_REMOVE) {
          const value = R.head(diffDelta);
          previous = value;
          current = Array.isArray(value) ? [] : '';
        }
        // Setup the patch
        if (patch.replace) {
          patch.replace[field] = { current, previous };
        } else {
          patch.replace = { [field]: { current, previous } };
        }
      } else if (diffDelta[DIFF_TYPE] === DIFF_TYPE_ARRAY) {
        // Is an array changes
        const delta = R.dissoc(DIFF_TYPE, diffDelta);
        const deltaObjEntries = Object.entries(delta);
        for (let indexDelta = 0; indexDelta < deltaObjEntries.length; indexDelta += 1) {
          const [, diffData] = deltaObjEntries[indexDelta];
          if (diffData.length === DIFF_ADDED) {
            if (patch.add) {
              patch.add[field] = diffData;
            } else {
              patch.add = { [field]: diffData };
            }
          }
          if (diffData.length === DIFF_REMOVE) {
            const removedValue = R.head(diffData);
            const removeVal = Array.isArray(removedValue) ? removedValue : [removedValue];
            if (patch.remove) {
              patch.remove[field] = removeVal;
            } else {
              patch.remove = { [field]: removeVal };
            }
          }
        }
      } else {
        // Is a internal complex object, like extensions
        // TODO @JRI
      }
    }
  }
  return patch;
};

// Merge
const buildMergeEvent = (user, initialInstance, mergedInstance, sourceEntities, impacts) => {
  const patch = computeMergeDifferential(initialInstance, mergedInstance);
  const message = generateMergeMessage(initialInstance, sourceEntities);
  const data = convertInstanceToStix(mergedInstance);
  const { updatedRelations, dependencyDeletions } = impacts;
  data.x_opencti_patch = patch;
  data.x_opencti_context = {
    sources: R.map((s) => convertInstanceToStix(s), sourceEntities),
    deletions: R.map((s) => convertInstanceToStix(s), dependencyDeletions),
    shifts: updatedRelations,
  };
  return buildEvent(EVENT_TYPE_MERGE, user, mergedInstance.object_marking_refs, message, data);
};
export const storeMergeEvent = async (user, initialInstance, mergedInstance, sourceEntities, impacts) => {
  try {
    const event = buildMergeEvent(user, initialInstance, mergedInstance, sourceEntities, impacts);
    await pushToStream(clientBase, event);
  } catch (e) {
    throw DatabaseError('Error in store merge event', { error: e });
  }
};
// Update
export const buildUpdateEvent = (user, instance, patch, opts = {}) => {
  const { withoutMessage = false } = opts;
  // dataUpdate can be empty
  if (isEmptyField(patch)) {
    return null;
  }
  // Build the final data
  const data = { ...instance, x_opencti_patch: patch };
  // Generate the message
  const message = withoutMessage ? '-' : generateUpdateMessage(patch);
  // Build and send the event
  const dataEvent = convertInstanceToStix(data);
  return buildEvent(
    EVENT_TYPE_UPDATE,
    user,
    instance.object_marking_refs,
    message,
    dataEvent,
    opts.commitMessage,
    opts.references
  );
};
export const storeUpdateEvent = async (user, instance, patchInputs, opts = {}) => {
  const { mustBeRepublished = false } = opts;
  // updateEvents -> [{ operation, input }]
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    try {
      const patch = updateInputsToPatch(patchInputs);
      const eventData = mustBeRepublished ? instance : getInstanceIdentifiers(instance);
      const event = buildUpdateEvent(user, eventData, patch, opts);
      // Push the event in the stream only if instance is in "real index"
      if (mustBeIncludeInStream(instance)) {
        await pushToStream(clientBase, event);
      }
      return event;
    } catch (e) {
      throw DatabaseError('Error in store update event', { error: e });
    }
  }
  return null;
};
// Create
export const buildCreateEvent = async (user, instance, input, loaders, opts = {}) => {
  const { withoutMessage = false } = opts;
  const { stixLoadById, connectionLoaders } = loaders;
  // If internal relation, publish an update instead of a creation
  if (isStixEmbeddedRelationship(instance.entity_type)) {
    const mustRepublished = instance.entity_type === RELATION_OBJECT_MARKING;
    let publishedInstance;
    if (mustRepublished) {
      publishedInstance = await stixLoadById(user, instance.from.internal_id);
    } else if (instance.from.base_type === BASE_TYPE_RELATION) {
      const instanceWithConnections = await connectionLoaders(user, instance.from);
      publishedInstance = getInstanceIdentifiers(instanceWithConnections);
    } else {
      publishedInstance = getInstanceIdentifiers(instance.from);
    }
    const key = STIX_EMBEDDED_RELATION_TO_FIELD[instance.entity_type];
    if (isSingleStixEmbeddedRelationship(instance.entity_type)) {
      const inputVal = { key, value: [instance.to], previous: null };
      const patch = updateInputsToPatch([inputVal]);
      return buildUpdateEvent(user, publishedInstance, patch, opts);
    }
    const inputVal = { key, value: [instance.to], operation: UPDATE_OPERATION_ADD };
    const patch = updateInputsToPatch([inputVal]);
    return buildUpdateEvent(user, publishedInstance, patch, opts);
  }
  // Convert the input to data
  const mergedData = { ...instance, ...input };
  const data = convertInstanceToStix(mergedData);
  // Generate the message
  const message = withoutMessage ? '-' : generateCreateMessage(mergedData);
  // Build and send the event
  const inputMarkings = (input.objectMarking || []).map((m) => m.internal_id);
  return buildEvent(EVENT_TYPE_CREATE, user, inputMarkings, message, data);
};
export const buildScanEvent = (user, instance) => {
  const data = convertInstanceToStix(instance);
  return buildEvent(EVENT_TYPE_CREATE, user, instance.object_marking_refs ?? [], '-', data);
};

export const storeCreateEvent = async (user, instance, input, loaders) => {
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    try {
      const event = await buildCreateEvent(user, instance, input, loaders);
      // Push the event in the stream only if instance is in "real index"
      if (mustBeIncludeInStream(instance)) {
        await pushToStream(clientBase, event);
      }
      return event;
    } catch (e) {
      throw DatabaseError('Error in store create event', { error: e });
    }
  }
  return null;
};
// Delete
export const buildDeleteEvent = async (user, instance, dependencyDeletions, loaders, opts = {}) => {
  const { withoutMessage = false } = opts;
  const { stixLoadById, connectionLoaders } = loaders;
  // If internal relation, publish an update instead of a creation
  if (isStixEmbeddedRelationship(instance.entity_type)) {
    const mustRepublished = instance.entity_type === RELATION_OBJECT_MARKING;
    let publishedInstance;
    if (mustRepublished) {
      publishedInstance = await stixLoadById(user, instance.from.internal_id);
    } else if (instance.from.base_type === BASE_TYPE_RELATION) {
      const instanceWithConnections = await connectionLoaders(user, instance.from);
      publishedInstance = getInstanceIdentifiers(instanceWithConnections);
    } else {
      publishedInstance = getInstanceIdentifiers(instance.from);
    }
    const key = STIX_EMBEDDED_RELATION_TO_FIELD[instance.entity_type];
    if (isSingleStixEmbeddedRelationship(instance.entity_type)) {
      const inputVal = { key, value: null, previous: [instance.to] };
      const patch = updateInputsToPatch([inputVal]);
      return buildUpdateEvent(user, publishedInstance, patch, opts);
    }
    const inputVal = { key, value: [instance.to], operation: UPDATE_OPERATION_REMOVE };
    const patch = updateInputsToPatch([inputVal]);
    return buildUpdateEvent(user, publishedInstance, patch, opts);
  }
  // Convert the input to data
  const data = convertInstanceToStix(instance);
  // Generate the message
  const message = withoutMessage ? '-' : generateDeleteMessage(instance);
  data.x_opencti_context = { deletions: R.map((s) => convertInstanceToStix(s), dependencyDeletions) };
  return buildEvent(EVENT_TYPE_DELETE, user, instance.object_marking_refs, message, data);
};
export const storeDeleteEvent = async (user, instance, dependencyDeletions, loaders) => {
  try {
    if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
      const event = await buildDeleteEvent(user, instance, dependencyDeletions, loaders);
      // Push the event in the stream only if instance is in "real index"
      if (mustBeIncludeInStream(instance)) {
        await pushToStream(clientBase, event);
      }
      return event;
    }
  } catch (e) {
    throw DatabaseError('Error in store delete event', { error: e });
  }
  return null;
};

const mapStreamToJS = ([id, data]) => {
  const count = data.length / 2;
  const result = { eventId: id };
  for (let i = 0; i < count; i += 1) {
    result[data[2 * i]] = JSON.parse(data[2 * i + 1]);
  }
  return result;
};
export const fetchStreamInfo = async () => {
  const res = await clientBase.call('XINFO', 'STREAM', REDIS_STREAM_NAME);
  const [, size, , , , , , lastId, , , , [firstId], ,] = res;
  const firstEventDate = utcDate(parseInt(firstId.split('-')[0], 10)).toISOString();
  const lastEventDate = utcDate(parseInt(lastId.split('-')[0], 10)).toISOString();
  return { lastEventId: lastId, firstEventId: firstId, firstEventDate, lastEventDate, streamSize: size };
};

const processStreamResult = async (results, callback) => {
  const streamData = R.map((r) => mapStreamToJS(r), results);
  const lastElement = R.last(streamData);
  // Prepare the elements
  const processedResults = [];
  for (let index = 0; index < streamData.length; index += 1) {
    const dataElement = streamData[index];
    const { eventId, type, markings, origin, data, message, commit, references, version } = dataElement;
    const eventData = { markings, origin, data, message, commit, references, version };
    processedResults.push({ id: eventId, topic: type, data: eventData });
  }
  // Callback the data
  await callback(processedResults);
  return lastElement.eventId;
};

const WAIT_TIME = 1000;
const MAX_RANGE_MESSAGES = 500;
export const createStreamProcessor = (user, provider, callback, maxRange = MAX_RANGE_MESSAGES) => {
  let client;
  let startEventId;
  let processingLoopPromise;
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
      const opts = ['BLOCK', WAIT_TIME, 'COUNT', maxRange, 'STREAMS', REDIS_STREAM_NAME, startEventId];
      const streamResult = await client.xread(...opts);
      if (streamResult && streamResult.length > 0) {
        const [, results] = R.head(streamResult);
        const lastElementId = await processStreamResult(results, callback);
        startEventId = lastElementId || startEventId;
      }
    } catch (err) {
      logApp.error('Error in redis stream read', { error: err });
    }
    return true;
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
      client = await createRedisClient(provider); // Create client for this processing loop
      logApp.info(`[STREAM] Starting stream processor for ${provider}`);
      processingLoopPromise = processingLoop();
    },
    shutdown: async () => {
      logApp.info(`[STREAM] Shutdown stream processor for ${user.user_email}`);
      streamListening = false;
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
      if (client) {
        await client.disconnect();
      }
    },
  };
};
// endregion

// region work handling
export const redisDeleteWork = async (internalIds) => {
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  return redisTx(clientBase, (tx) => {
    tx.del(...ids);
  });
};
export const redisCreateWork = async (element) => {
  return redisTx(clientBase, (tx) => {
    const data = R.flatten(R.toPairs(element));
    tx.hset(element.internal_id, data);
  });
};
export const redisGetWork = async (internalId) => {
  const rawElement = await clientBase.call('HGETALL', internalId);
  return R.fromPairs(R.splitEvery(2, rawElement));
};
export const redisUpdateWork = async (id, input) => {
  const data = R.flatten(R.toPairs(input));
  return redisTx(clientBase, (tx) => {
    tx.hset(id, data);
  });
};
export const redisUpdateWorkFigures = async (workId) => {
  const timestamp = now();
  const [, , fetched] = await redisTx(clientBase, async (tx) => {
    await updateObjectCounterRaw(tx, workId, 'import_processed_number', 1);
    await updateObjectRaw(tx, workId, { import_last_processed: timestamp });
    await tx.hgetall(workId);
  });
  const updatedMetrics = R.last(fetched);
  const { import_processed_number: pn, import_expected_number: en } = updatedMetrics;
  return { isComplete: parseInt(pn, 10) === parseInt(en, 10), total: pn, expected: en };
};
export const redisUpdateActionExpectation = async (user, workId, expectation) => {
  await redisTx(clientBase, async (tx) => {
    await updateObjectCounterRaw(tx, workId, 'import_expected_number', expectation);
  });
  return workId;
};
// endregion
