import { readFileSync } from 'fs';
import Redis from 'ioredis';
import Redlock from 'redlock';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
import { create as createJsonDiff } from 'jsondiffpatch';
import conf, { configureCA, logApp } from '../config/conf';
import {
  generateLogMessage,
  isEmptyField,
  isNotEmptyField,
  relationTypeToInputName,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_CHANGE,
  UPDATE_OPERATION_REMOVE,
} from './utils';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import { EVENT_TYPE_CREATE, EVENT_TYPE_DELETE, EVENT_TYPE_MERGE, EVENT_TYPE_UPDATE } from './rabbitmq';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { buildStixData, stixDataConverter } from './stix';
import { DatabaseError, FunctionalError, UnsupportedError } from '../config/errors';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { MARKING_DEFINITION_STATEMENT } from '../schema/stixMetaObject';
import { now } from '../utils/format';
import RedisStore from './sessionStore-redis';
import SessionStoreMemory from './sessionStore-memory';
import { RELATION_OBJECT_MARKING } from '../schema/stixMetaRelationship';

const USE_SSL = conf.get('redis:use_ssl');
const REDIS_CA = conf.get('redis:ca').map((path) => readFileSync(path));

const BASE_DATABASE = 0; // works key for tracking / stream
export const CONTEXT_DATABASE = 1; // locks / user context
export const SESSION_DATABASE = 2; // locks / user context
const OPENCTI_STREAM = 'stream.opencti';
const REDIS_EXPIRE_TIME = 90;

const redisOptions = (database) => ({
  lazyConnect: true,
  db: database,
  port: conf.get('redis:port'),
  host: conf.get('redis:hostname'),
  tls: USE_SSL ? configureCA(REDIS_CA) : null,
  username: conf.get('redis:username'),
  password: conf.get('redis:password'),
  retryStrategy: /* istanbul ignore next */ (times) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 2,
  showFriendlyErrorStack: true,
});

export const pubsub = new RedisPubSub({
  publisher: new Redis(redisOptions()),
  subscriber: new Redis(redisOptions()),
});
export const createRedisClient = async (database = BASE_DATABASE) => {
  const client = new Redis(redisOptions(database));
  if (client.status !== 'ready') {
    await client.connect().catch(() => {
      throw DatabaseError('Redis seems down');
    });
  }
  client.on('connect', () => logApp.debug('[REDIS] Redis client connected'));
  return client;
};

let clientBase = null;
let clientContext = null;
export const redisInitializeClients = async () => {
  clientBase = await createRedisClient(BASE_DATABASE);
  clientContext = await createRedisClient(CONTEXT_DATABASE);
};
export const createMemorySessionStore = () => {
  return new SessionStoreMemory({
    checkPeriod: 3600000, // prune expired entries every 1h
  });
};
export const createRedisSessionStore = () => {
  return new RedisStore(clientContext);
};

export const redisIsAlive = async () => {
  if (clientBase.status !== 'ready' || clientContext.status !== 'ready') {
    /* istanbul ignore next */
    throw DatabaseError('Redis seems down');
  }
  return true;
};
export const getRedisVersion = async () => {
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
  await tx.call('HSET', id, data);
};
export const updateObjectCounterRaw = async (tx, id, field, number) => {
  await tx.call('HINCRBY', id, field, number);
};
// endregion

// region concurrent deletion
export const redisAddDeletions = async (internalIds) => {
  const deletionId = new Date().getTime();
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  return redisTx(clientContext, (tx) => {
    tx.call('SETEX', `deletion-${deletionId}`, REDIS_EXPIRE_TIME, JSON.stringify(ids));
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
const buildEvent = (eventType, user, markings, message, data) => {
  if (!data.id || !data.x_opencti_id || !data.type) {
    throw UnsupportedError('Stream event requires id, type and x_opencti_id');
  }
  const secureMarkings = R.filter((m) => m.definition_type !== MARKING_DEFINITION_STATEMENT, markings || []);
  const eventMarkingIds = R.map((i) => i.standard_id, secureMarkings);
  return {
    version: '2', // Event version.
    type: eventType,
    origin: user.origin,
    markings: eventMarkingIds,
    message,
    data,
  };
};
const pushToStream = (client, event) => {
  if (streamTrimming) {
    return client.call('XADD', OPENCTI_STREAM, 'MAXLEN', '~', streamTrimming, '*', ...mapJSToStream(event));
  }
  return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
};
const DIFF_ADDED = 1;
const DIFF_CHANGE = 2;
const DIFF_REMOVE = 3;
const DIFF_TYPE = '_t';
const DIFF_TYPE_ARRAY = 'a';
export const computeMergeDifferential = (initialInstance, mergedInstance) => {
  const convertInit = buildStixData(initialInstance, { patchGeneration: true });
  const convertMerged = buildStixData(mergedInstance, { patchGeneration: true });
  const diffGenerator = createJsonDiff({
    objectHash: (obj) => {
      return obj.x_opencti_internal_id;
    },
  });
  const diff = diffGenerator.diff(convertInit, convertMerged);
  const patch = {};
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
  return patch;
};
export const storeMergeEvent = async (user, initialInstance, mergedInstance, sourceEntities) => {
  try {
    const patch = computeMergeDifferential(initialInstance, mergedInstance);
    const message = generateLogMessage(EVENT_TYPE_MERGE, initialInstance, sourceEntities);
    const data = buildStixData(mergedInstance);
    data.x_opencti_patch = patch;
    data.sources = R.map((s) => buildStixData(s), sourceEntities);
    const event = buildEvent(EVENT_TYPE_MERGE, user, mergedInstance.objectMarking, message, data);
    return pushToStream(clientBase, event);
  } catch (e) {
    throw DatabaseError('Error in store merge event', { error: e });
  }
};
export const storeUpdateEvent = async (user, instance, updateEvents) => {
  // updateEvents -> [{ operation, input }]
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    try {
      const convertedInputs = updateEvents.map((i) => {
        const [k, v] = R.head(Object.entries(i));
        const convert = stixDataConverter(v, { patchGeneration: true });
        return isNotEmptyField(convert) ? { [k]: convert } : null;
      });
      const dataPatch = R.mergeAll(convertedInputs);
      // dataUpdate can be empty
      if (isEmptyField(dataPatch)) {
        return true;
      }
      // else just continue as usual
      const data = {
        standard_id: instance.standard_id,
        internal_id: instance.internal_id,
        entity_type: instance.entity_type,
        x_opencti_patch: dataPatch,
      };
      if (instance.identity_class) {
        data.identity_class = instance.identity_class;
      }
      if (instance.x_opencti_location_type) {
        data.x_opencti_location_type = instance.x_opencti_location_type;
      }
      // Generate the message
      const operation = updateEvents.length === 1 ? R.head(Object.keys(R.head(updateEvents))) : UPDATE_OPERATION_CHANGE;
      const messageInput = R.mergeAll(updateEvents.map((i) => stixDataConverter(R.head(Object.values(i)))));
      const message = generateLogMessage(operation, instance, messageInput);
      // Build and send the event
      const dataEvent = buildStixData(data);
      const event = buildEvent(EVENT_TYPE_UPDATE, user, instance.objectMarking, message, dataEvent);
      return pushToStream(clientBase, event);
    } catch (e) {
      throw DatabaseError('Error in store update event', { error: e });
    }
  }
  return true;
};
export const storeCreateEvent = async (user, instance, input, stixLoader) => {
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    try {
      // If relationship but not stix core
      const isCore = isStixCoreRelationship(instance.entity_type);
      const isSighting = isStixSightingRelationship(instance.entity_type);
      // If internal relation, publish an update instead of a creation
      if (isStixRelationship(instance.entity_type) && !isCore && !isSighting) {
        const field = relationTypeToInputName(instance.entity_type);
        const inputUpdate = { [field]: input.to };
        const mustRepublished = instance.entity_type === RELATION_OBJECT_MARKING;
        let publishedInstance = instance.from;
        if (mustRepublished) {
          publishedInstance = await stixLoader(user, instance.from.internal_id);
        }
        return storeUpdateEvent(user, publishedInstance, [{ [UPDATE_OPERATION_ADD]: inputUpdate }]);
      }
      // Create of an event for
      const identifiers = {
        standard_id: instance.standard_id,
        internal_id: instance.internal_id,
        entity_type: instance.entity_type,
      };
      // Convert the input to data
      const data = buildStixData({ ...identifiers, ...input }, { diffMode: false });
      // Generate the message
      const message = generateLogMessage(EVENT_TYPE_CREATE, instance, data);
      // Build and send the event
      const event = buildEvent(EVENT_TYPE_CREATE, user, input.objectMarking, message, data);
      return pushToStream(clientBase, event);
    } catch (e) {
      throw DatabaseError('Error in store create event', { error: e });
    }
  }
  return true;
};
export const storeDeleteEvent = async (user, instance, stixLoader) => {
  try {
    if (isStixObject(instance.entity_type)) {
      const message = generateLogMessage(EVENT_TYPE_DELETE, instance);
      const data = buildStixData(instance, { diffMode: false });
      const event = buildEvent(EVENT_TYPE_DELETE, user, instance.objectMarking, message, data);
      return pushToStream(clientBase, event);
    }
    if (isStixRelationship(instance.entity_type)) {
      const isCore = isStixCoreRelationship(instance.entity_type);
      const isSighting = isStixSightingRelationship(instance.entity_type);
      if (!isCore && !isSighting) {
        const field = relationTypeToInputName(instance.entity_type);
        const inputUpdate = { [field]: instance.to };
        const mustRepublished = instance.entity_type === RELATION_OBJECT_MARKING;
        let publishedInstance = instance.from;
        if (mustRepublished) {
          publishedInstance = await stixLoader(user, instance.from.internal_id);
        }
        return storeUpdateEvent(user, publishedInstance, [{ [UPDATE_OPERATION_REMOVE]: inputUpdate }]);
      }
      // for other deletion, just produce a delete event
      const message = generateLogMessage(EVENT_TYPE_DELETE, instance);
      const data = buildStixData(instance, { diffMode: false });
      const event = buildEvent(EVENT_TYPE_DELETE, user, instance.objectMarking, message, data);
      return pushToStream(clientBase, event);
    }
  } catch (e) {
    throw DatabaseError('Error in store delete event', { error: e });
  }
  return true;
};

const fetchStreamInfo = async () => {
  const res = await clientBase.call('XINFO', 'STREAM', OPENCTI_STREAM);
  const [, size, , , , , , lastId, , , , , ,] = res;
  return { lastEventId: lastId, streamSize: size };
};
const mapStreamToJS = ([id, data]) => {
  const count = data.length / 2;
  const result = { eventId: id };
  for (let i = 0; i < count; i += 1) {
    result[data[2 * i]] = JSON.parse(data[2 * i + 1]);
  }
  return result;
};
const processStreamResult = async (results, callback) => {
  const streamData = R.map((r) => mapStreamToJS(r), results);
  const lastElement = R.last(streamData);
  // Prepare the elements
  const processedResults = [];
  for (let index = 0; index < streamData.length; index += 1) {
    const dataElement = streamData[index];
    const { eventId, type, markings, origin, data, message, version } = dataElement;
    const eventData = { markings, origin, data, message, version };
    processedResults.push({ id: eventId, topic: type, data: eventData });
  }
  // Callback the data
  await callback(processedResults);
  return lastElement.eventId;
};

let processingLoopPromise;
const WAIT_TIME = 1000;
const MAX_RANGE_MESSAGES = 500;
export const createStreamProcessor = (user, callback, maxRange = MAX_RANGE_MESSAGES) => {
  let client;
  let startEventId;
  let streamListening = true;
  const processInfo = async () => {
    return fetchStreamInfo();
  };
  const processStep = async () => {
    const streamResult = await client.xread(
      'BLOCK',
      WAIT_TIME,
      'COUNT',
      maxRange,
      'STREAMS',
      OPENCTI_STREAM,
      startEventId
    );
    // since previous call is async (and blocking) we should check if we are still running before processing the message
    if (!streamListening) {
      return false;
    }
    if (streamResult && streamResult.length > 0) {
      const [, results] = R.head(streamResult);
      const lastElementId = await processStreamResult(results, callback);
      startEventId = lastElementId || startEventId;
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
      if (isEmptyField(fromStart)) fromStart = 'live';
      startEventId = fromStart === 'live' ? '$' : fromStart;
      client = await createRedisClient(); // Create client for this processing loop
      logApp.info(`[STREAM] Starting stream processor for ${user.user_email}`);
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
    tx.call('DEL', ...ids);
  });
};
export const redisCreateWork = async (element) => {
  return redisTx(clientBase, (tx) => {
    const data = R.flatten(R.toPairs(element));
    tx.call('HSET', element.internal_id, data);
  });
};
export const redisGetWork = async (internalId) => {
  const rawElement = await clientBase.call('HGETALL', internalId);
  return R.fromPairs(R.splitEvery(2, rawElement));
};
export const redisUpdateWork = async (id, input) => {
  const data = R.flatten(R.toPairs(input));
  return redisTx(clientBase, (tx) => {
    tx.call('HSET', id, data);
  });
};
export const redisUpdateWorkFigures = async (workId) => {
  const timestamp = now();
  const [, , fetched] = await redisTx(clientBase, async (tx) => {
    await updateObjectCounterRaw(tx, workId, 'import_processed_number', 1);
    await updateObjectRaw(tx, workId, { import_last_processed: timestamp });
    await tx.call('HGETALL', workId);
  });
  const updatedMetrics = R.fromPairs(R.splitEvery(2, R.last(fetched)));
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
