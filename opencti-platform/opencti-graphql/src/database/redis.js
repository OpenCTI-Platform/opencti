import Redis from 'ioredis';
import Redlock from 'redlock';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
import conf, { logger } from '../config/conf';
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
import { buildStixData, convertTypeToStixType, stixDataConverter } from './stix';
import { DatabaseError } from '../config/errors';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { MARKING_DEFINITION_STATEMENT } from '../schema/stixMetaObject';

const OPENCTI_STREAM = 'stream.opencti';
const REDIS_EXPIRE_TIME = 90;
const redisOptions = {
  lazyConnect: true,
  port: conf.get('redis:port'),
  host: conf.get('redis:hostname'),
  password: conf.get('redis:password'),
  retryStrategy: /* istanbul ignore next */ (times) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 2,
};

let redis = null;
const createRedisClient = async () => {
  const client = new Redis(redisOptions);
  if (client.status !== 'ready') await client.connect();
  client.on('connect', () => logger.debug('[REDIS] Redis client connected'));
  return client;
};
const getClient = async () => {
  if (redis) return redis;
  redis = createRedisClient();
  return redis;
};
export const pubsub = new RedisPubSub({
  publisher: new Redis(redisOptions),
  subscriber: new Redis(redisOptions),
});
export const redisIsAlive = async () => {
  const client = await getClient();
  if (client.status !== 'ready') {
    /* istanbul ignore next */
    throw DatabaseError('Redis seems down');
  }
  return true;
};
export const getRedisVersion = async () => {
  const client = await getClient();
  return client.serverInfo.redis_version;
};

/* istanbul ignore next */
export const notify = (topic, instance, user, context) => {
  pubsub.publish(topic, { instance, user, context });
  return instance;
};

// region user context
export const setEditContext = async (user, instanceId, input) => {
  const client = await getClient();
  const data = R.assoc('name', user.user_email, input);
  return client.set(
    `edit:${instanceId}:${user.id}`,
    JSON.stringify(data),
    'ex',
    5 * 60 // Key will be remove if user is not active during 5 minutes
  );
};
export const fetchEditContext = async (instanceId) => {
  const client = await getClient();
  return new Promise((resolve, reject) => {
    const elementsPromise = [];
    const stream = client.scanStream({
      match: `edit:${instanceId}:*`,
      count: 100,
    });
    stream.on('data', (resultKeys) => {
      for (let i = 0; i < resultKeys.length; i += 1) {
        elementsPromise.push(client.get(resultKeys[i]));
      }
    });
    stream.on('error', (error) => {
      /* istanbul ignore next */
      reject(error);
    });
    stream.on('end', () => {
      Promise.all(elementsPromise).then((data) => {
        const elements = R.map((d) => JSON.parse(d), data);
        resolve(elements);
      });
    });
  });
};
export const delEditContext = async (user, instanceId) => {
  const client = await getClient();
  return client.del(`edit:${instanceId}:${user.id}`);
};
export const delUserContext = async (user) => {
  const client = await getClient();
  return new Promise((resolve, reject) => {
    const stream = client.scanStream({
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
        client.del(keys);
      }
      resolve();
    });
  });
};
// endregion

// region cache for access token
export const getAccessCache = async (tokenUUID) => {
  const client = await getClient();
  const data = await client.get(`access-${tokenUUID}`);
  return data && JSON.parse(data);
};
export const storeUserAccessCache = async (tokenUUID, access, expiration = REDIS_EXPIRE_TIME) => {
  const client = await getClient();
  const val = JSON.stringify(access);
  await client.set(`access-${tokenUUID}`, val, 'ex', expiration);
  return access;
};
export const clearUserAccessCache = async (tokenUUID) => {
  const client = await getClient();
  await client.del(`access-${tokenUUID}`);
};
// endregion

// region locking
export const lockResource = async (resources) => {
  const locks = R.uniq(resources);
  const redisClient = await getClient();
  // Retry during 5 secs
  const retryCount = conf.get('app:concurrency:retry_count');
  const retryDelay = conf.get('app:concurrency:retry_delay');
  const retryJitter = conf.get('app:concurrency:retry_jitter');
  const maxTtl = conf.get('app:concurrency:max_ttl');
  const redlock = new Redlock([redisClient], { retryCount, retryDelay, retryJitter });
  const lock = await redlock.lock(locks, maxTtl); // Force unlock after 10 secs
  return {
    extend: () => true,
    unlock: async () => {
      try {
        await lock.unlock();
      } catch (e) {
        logger.debug(e, '[REDIS] Failed to unlock resource', { locks });
      }
    },
  };
};
// endregion

// region opencti stream
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
  const secureMarkings = R.filter((m) => m.definition_type !== MARKING_DEFINITION_STATEMENT, markings || []);
  const eventMarkingIds = R.map((i) => i.standard_id, secureMarkings);
  return {
    version: '1', // Event version.
    type: eventType,
    origin: user.origin,
    markings: eventMarkingIds,
    message,
    data,
  };
};
export const storeMergeEvent = async (user, instance, sourceEntities) => {
  try {
    const message = generateLogMessage(EVENT_TYPE_MERGE, instance);
    const data = {
      id: instance.standard_id,
      x_opencti_id: instance.internal_id,
      type: convertTypeToStixType(instance.entity_type),
      source_ids: R.map((s) => s.standard_id, sourceEntities),
    };
    const event = buildEvent(EVENT_TYPE_MERGE, user, instance.objectMarking, message, data);
    const client = await getClient();
    return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
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
        const convert = stixDataConverter(v);
        return isNotEmptyField(convert) ? { [k]: convert } : null;
      });
      const dataUpdate = R.mergeAll(convertedInputs);
      // dataUpdate can be empty
      if (isEmptyField(dataUpdate)) {
        return true;
      }
      // else just continue as usual1
      const data = {
        id: instance.standard_id,
        x_opencti_id: instance.internal_id,
        type: convertTypeToStixType(instance.entity_type),
        x_data_update: dataUpdate,
      };
      if (instance.hashes) {
        data.hashes = instance.hashes;
      }
      // Generate the message
      const operation = updateEvents.length === 1 ? R.head(Object.keys(R.head(updateEvents))) : UPDATE_OPERATION_CHANGE;
      const messageInput = R.mergeAll(updateEvents.map((i) => stixDataConverter(R.head(Object.values(i)))));
      const message = generateLogMessage(operation, instance, messageInput);
      // Build and send the event
      const event = buildEvent(EVENT_TYPE_UPDATE, user, instance.objectMarking, message, data);
      const client = await getClient();
      await client.xadd(OPENCTI_STREAM, '*', ...mapJSToStream(event));
    } catch (e) {
      throw DatabaseError('Error in store update event', { error: e });
    }
  }
  return true;
};
export const storeCreateEvent = async (user, instance, input) => {
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    try {
      // If relationship but not stix core
      const isCore = isStixCoreRelationship(instance.entity_type);
      const isSighting = isStixSightingRelationship(instance.entity_type);
      // If internal relation, publish an update instead of a creation
      if (isStixRelationship(instance.entity_type) && !isCore && !isSighting) {
        const field = relationTypeToInputName(instance.entity_type);
        const inputUpdate = { [field]: input.to };
        return storeUpdateEvent(user, instance.from, [{ [UPDATE_OPERATION_ADD]: inputUpdate }]);
      }
      // Create of an event for
      const identifiers = {
        standard_id: instance.standard_id,
        internal_id: instance.internal_id,
        entity_type: instance.entity_type,
      };
      // Convert the input to data
      const data = buildStixData({ ...identifiers, ...input });
      // Generate the message
      const message = generateLogMessage(EVENT_TYPE_CREATE, instance, data);
      // Build and send the event
      const event = buildEvent(EVENT_TYPE_CREATE, user, input.objectMarking, message, data);
      const client = await getClient();
      await client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
    } catch (e) {
      throw DatabaseError('Error in store create event', { error: e });
    }
  }
  return true;
};
export const storeDeleteEvent = async (user, instance) => {
  try {
    if (isStixObject(instance.entity_type)) {
      const message = generateLogMessage(EVENT_TYPE_DELETE, instance);
      const data = {
        id: instance.standard_id,
        x_opencti_id: instance.internal_id,
        type: convertTypeToStixType(instance.entity_type),
      };
      if (instance.hashes) {
        data.hashes = instance.hashes;
      }
      const event = buildEvent(EVENT_TYPE_DELETE, user, instance.objectMarking, message, data);
      const client = await getClient();
      return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
    }
    if (isStixRelationship(instance.entity_type)) {
      const isCore = isStixCoreRelationship(instance.entity_type);
      const isSighting = isStixSightingRelationship(instance.entity_type);
      if (!isCore && !isSighting) {
        const field = relationTypeToInputName(instance.entity_type);
        const inputUpdate = { [field]: instance.to };
        return storeUpdateEvent(user, instance.from, [{ [UPDATE_OPERATION_REMOVE]: inputUpdate }]);
      }
      // for other deletion, just produce a delete event
      const message = generateLogMessage(EVENT_TYPE_DELETE, instance);
      const data = {
        id: instance.standard_id,
        x_opencti_id: instance.internal_id,
        type: convertTypeToStixType(instance.entity_type),
        source_ref: instance.from.standard_id,
        x_opencti_source_ref: instance.from.internal_id,
        target_ref: instance.to.standard_id,
        x_opencti_target_ref: instance.to.internal_id,
      };
      const event = buildEvent(EVENT_TYPE_DELETE, user, instance.objectMarking, message, data);
      const client = await getClient();
      return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
    }
  } catch (e) {
    throw DatabaseError('Error in store delete event', { error: e });
  }
  return true;
};

const fetchStreamInfo = async (client) => {
  const res = await client.call('XINFO', 'STREAM', OPENCTI_STREAM);
  // eslint-disable-next-line
  const [, size, , keys, , nodes, , lastId, , groups, , firstEntry, , lastEntry] = res;
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
  for (let index = 0; index < streamData.length; index += 1) {
    const dataElement = streamData[index];
    const { eventId, type, markings, origin, data, message } = dataElement;
    const eventData = { markings, origin, data, message };
    // eslint-disable-next-line no-await-in-loop
    await callback(eventId, type, eventData);
  }
  return lastElement.eventId;
};

let processingLoopPromise;
let streamListening = true;
const MAX_RANGE_MESSAGES = 2000;
const WAIT_TIME = 20000;
export const createStreamProcessor = (callback) => {
  let startEventId;
  const processInfo = async () => {
    const client = await getClient();
    return fetchStreamInfo(client);
  };
  const processStep = async (client) => {
    const streamResult = await client.xread('BLOCK', WAIT_TIME, 'COUNT', 1, 'STREAMS', OPENCTI_STREAM, startEventId);
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
    const client = await createRedisClient();
    const streamInfo = await processInfo();
    startEventId = streamInfo.lastEventId;
    while (streamListening) {
      // eslint-disable-next-line no-await-in-loop
      if (!(await processStep(client))) {
        break;
      }
    }
  };
  return {
    info: async () => processInfo(),
    start: async () => {
      logger.info('[STREAM] Starting streaming processor');
      processingLoopPromise = processingLoop();
    },
    shutdown: async () => {
      logger.info('[STREAM] Shutdown streaming processor');
      streamListening = false;
      if (processingLoopPromise) {
        await processingLoopPromise;
      }
    },
  };
};
export const getStreamRange = async (from, limit, callback) => {
  const client = await createRedisClient();
  const size = limit > MAX_RANGE_MESSAGES ? MAX_RANGE_MESSAGES : limit;
  return client.call('XRANGE', OPENCTI_STREAM, from, '+', 'COUNT', size).then(async (results) => {
    if (results && results.length > 0) {
      await processStreamResult(results, callback);
    }
    const lastResult = R.last(results);
    return { lastEventId: R.head(lastResult) };
  });
};
// endregion

// region
// Simple object that contains only basic data (string, number)
export const redisTx = async (callback) => {
  const client = await getClient();
  const tx = client.multi();
  try {
    await callback(tx);
    return tx.exec();
  } catch (e) {
    throw DatabaseError('Redis Tx error', { error: e });
  }
};
export const basicObjectDelete = async (internalIds) => {
  const ids = Array.isArray(internalIds) ? internalIds : [internalIds];
  return redisTx((tx) => {
    tx.call('DEL', ...ids);
  });
};
export const basicObjectCreation = async (element) => {
  return redisTx((tx) => {
    const data = R.flatten(R.toPairs(element));
    tx.call('HSET', element.internal_id, data);
  });
};
export const updateObjectRaw = async (tx, id, input) => {
  const data = R.flatten(R.toPairs(input));
  await tx.call('HSET', id, data);
};
export const updateObject = async (id, input) => {
  const data = R.flatten(R.toPairs(input));
  return redisTx((tx) => {
    tx.call('HSET', id, data);
  });
};
export const updateObjectCounterRaw = async (tx, id, field, number) => {
  await tx.call('HINCRBY', id, field, number);
};
export const fetchBasicObject = async (internalId) => {
  const client = await getClient();
  const rawElement = await client.call('HGETALL', internalId);
  return R.fromPairs(R.splitEvery(2, rawElement));
};
// endregion
