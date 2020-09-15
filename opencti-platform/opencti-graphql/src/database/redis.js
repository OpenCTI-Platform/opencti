import Redis from 'ioredis';
import Redlock from 'redlock';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
import conf, { logger } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { generateLogMessage, relationTypeToInputName, utcDate } from './utils';
import { isStixObject } from '../schema/stixCoreObject';
import { isStixRelationship } from '../schema/stixRelationship';
import {
  EVENT_TYPE_CREATE,
  EVENT_TYPE_DELETE,
  EVENT_TYPE_UPDATE,
  UPDATE_OPERATION_ADD,
  UPDATE_OPERATION_REMOVE,
} from './rabbitmq';
import { isStixCoreRelationship } from '../schema/stixCoreRelationship';
import { buildStixData, stixDataConverter } from './stix';

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
const initRedisClient = async () => {
  redis = redis || new Redis(redisOptions);
  if (redis.status !== 'ready') {
    await redis.connect();
  }
  redis.on('error', (error) => {
    /* istanbul ignore next */
    logger.error('[REDIS] An error occurred on redis', { error });
  });
  return redis;
};
const getClient = async () => {
  if (redis) return redis;
  return initRedisClient();
};
export const pubsub = new RedisPubSub({
  publisher: new Redis(redisOptions),
  subscriber: new Redis(redisOptions),
});
export const redisIsAlive = async () => {
  const client = await getClient();
  if (client.status !== 'ready') {
    /* istanbul ignore next */
    throw DatabaseError('redis seems down');
  }
  return true;
};
export const getRedisVersion = () => {
  return getClient().then((client) => client.serverInfo.redis_version);
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
  const redisClient = await getClient();
  // Retry during 5 secs
  const redlock = new Redlock([redisClient], { retryCount: 10, retryDelay: 500 });
  const lock = await redlock.lock(resources, 10000); // Force unlock after 10 secs
  return {
    extend: () => true,
    unlock: async () => {
      try {
        await lock.unlock();
      } catch (e) {
        logger.debug(e, 'Failed to unlock resource', { resources });
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
export const storeUpdateEvent = async (user, operation, instance, input) => {
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    const convertedInput = stixDataConverter(input);
    // else just continue as usual
    const now = utcDate().toISOString();
    const data = {
      id: instance.standard_id,
      x_opencti_id: instance.internal_id,
      type: instance.entity_type.toLowerCase(),
      x_data_update: { [operation]: convertedInput },
    };
    // Generate the message
    const message = generateLogMessage(operation, user, instance, convertedInput);
    // Build and send the event
    const event = {
      type: EVENT_TYPE_UPDATE,
      markings: R.map((i) => i.standard_id, instance.objectMarking || []),
      user: user.id || user.name,
      timestamp: now,
      data,
      message,
    };
    const client = await getClient();
    return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
  }
  return true;
};
export const storeCreateEvent = async (user, instance, input) => {
  if (isStixObject(instance.entity_type) || isStixRelationship(instance.entity_type)) {
    // If relationship but not stix core
    if (isStixRelationship(instance.entity_type) && !isStixCoreRelationship(instance.entity_type)) {
      const field = relationTypeToInputName(instance.entity_type);
      return storeUpdateEvent(user, UPDATE_OPERATION_ADD, instance.from, { [field]: input.to });
    }
    // Create of an event for
    const identifiers = {
      standard_id: instance.standard_id,
      internal_id: instance.internal_id,
      entity_type: instance.entity_type,
    };
    // Convert the input to data
    const data = buildStixData(Object.assign(identifiers, input));
    // Generate the message
    const message = generateLogMessage(EVENT_TYPE_CREATE, user, instance, data);
    // Build and send the event
    const now = utcDate().toISOString();
    const event = {
      type: EVENT_TYPE_CREATE,
      markings: data.object_marking_refs || [],
      user: user.id || user.name,
      timestamp: now,
      data,
      message,
    };
    const client = await getClient();
    return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
  }
  return true;
};
export const storeDeleteEvent = async (user, instance) => {
  const now = utcDate().toISOString();
  if (isStixObject(instance.entity_type)) {
    const message = generateLogMessage(EVENT_TYPE_DELETE, user, instance);
    const data = {
      id: instance.standard_id,
      x_opencti_id: instance.internal_id,
      type: instance.entity_type.toLowerCase(),
    };
    const event = {
      type: EVENT_TYPE_DELETE,
      markings: R.map((i) => i.standard_id, instance.objectMarking || []),
      user: user.id || user.name,
      timestamp: now,
      data,
      message,
    };
    const client = await getClient();
    return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
  }
  if (isStixRelationship(instance.entity_type)) {
    if (!isStixCoreRelationship(instance.entity_type)) {
      const field = relationTypeToInputName(instance.entity_type);
      return storeUpdateEvent(user, UPDATE_OPERATION_REMOVE, instance.from, { [field]: instance.to });
    }
    // for other deletion, just produce a delete event
    const message = generateLogMessage(EVENT_TYPE_DELETE, user, instance);
    const data = {
      id: instance.standard_id,
      x_opencti_id: instance.internal_id,
      type: instance.entity_type.toLowerCase(),
      source_ref: instance.from.standard_id,
      target_ref: instance.to.standard_id,
    };
    const event = {
      type: EVENT_TYPE_DELETE,
      markings: R.map((i) => i.standard_id, instance.objectMarking || []),
      user: user.id || user.name,
      timestamp: now,
      data,
      message,
    };
    const client = await getClient();
    return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
  }
  return true;
};

let streamListening = true;
const fetchStreamInfo = async (client) => {
  const res = await client.call('XINFO', 'STREAM', OPENCTI_STREAM);
  // eslint-disable-next-line
  const [, size,, keys,, nodes,, lastId,, groups,, firstEntry,, lastEntry] = res;
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
const processStreamResult = (results, callback) => {
  const streamData = R.map((r) => mapStreamToJS(r), results);
  const lastElement = R.last(streamData);
  for (let index = 0; index < streamData.length; index += 1) {
    const dataElement = streamData[index];
    const { eventId, type, markings, user, timestamp, data, message } = dataElement;
    const eventData = { user, markings, timestamp, data, message };
    callback(eventId, type, eventData);
  }
  return lastElement.eventId;
};
export const listenStream = async (callback) => {
  const client = await getClient();
  const streamInfo = await fetchStreamInfo(client);
  let startEventId = streamInfo.lastEventId;
  const processStep = () => {
    return client.xread('BLOCK', 1, 'COUNT', 1, 'STREAMS', OPENCTI_STREAM, startEventId).then(async (streamResult) => {
      if (streamResult && streamResult.length > 0) {
        const [, results] = R.head(streamResult);
        const lastElementId = processStreamResult(results, callback);
        startEventId = lastElementId || startEventId;
      }
      return true;
    });
  };
  const processingLoop = async () => {
    while (streamListening) {
      // eslint-disable-next-line no-await-in-loop
      await processStep();
    }
  };
  // noinspection ES6MissingAwait
  processingLoop();
  return {
    info: () => streamInfo,
    shutdown: () => {
      streamListening = false;
    },
  };
};
export const catchup = async (from, limit, callback) => {
  const client = await getClient();
  const size = limit > 50 ? 50 : limit;
  return client.call('XRANGE', OPENCTI_STREAM, from, '+', 'COUNT', size).then(async (results) => {
    if (results && results.length > 0) {
      processStreamResult(results, callback);
    }
    return true;
  });
};
// endregion
