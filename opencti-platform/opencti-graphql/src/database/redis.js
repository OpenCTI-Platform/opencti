import { readFileSync } from 'fs';
import Redis from 'ioredis';
import Redlock from 'redlock';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import * as R from 'ramda';
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
import { buildStixData, convertTypeToStixType, stixDataConverter } from './stix';
import { DatabaseError, FunctionalError } from '../config/errors';
import { isStixSightingRelationship } from '../schema/stixSightingRelationship';
import { MARKING_DEFINITION_STATEMENT } from '../schema/stixMetaObject';
import { now } from '../utils/format';
import RedisStore from './sessionStore-redis';
import SessionStoreMemory from './sessionStore-memory';

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
const pushToStream = (client, event) => {
  if (streamTrimming) {
    return client.call('XADD', OPENCTI_STREAM, 'MAXLEN', '~', streamTrimming, '*', ...mapJSToStream(event));
  }
  return client.call('XADD', OPENCTI_STREAM, '*', ...mapJSToStream(event));
};
export const storeMergeEvent = async (user, instance, sourceEntities) => {
  try {
    const message = generateLogMessage(EVENT_TYPE_MERGE, instance, sourceEntities);
    const data = {
      id: instance.standard_id,
      x_opencti_id: instance.internal_id,
      type: convertTypeToStixType(instance.entity_type),
      source_ids: R.map((s) => s.standard_id, sourceEntities),
    };
    const event = buildEvent(EVENT_TYPE_MERGE, user, instance.objectMarking, message, data);
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
      return pushToStream(clientBase, event);
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
      return pushToStream(clientBase, event);
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
  for (let index = 0; index < streamData.length; index += 1) {
    const dataElement = streamData[index];
    const { eventId, type, markings, origin, data, message } = dataElement;
    const eventData = { markings, origin, data, message };
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
    return fetchStreamInfo();
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
  const processingLoop = async (client) => {
    const streamInfo = await processInfo();
    startEventId = streamInfo.lastEventId;
    while (streamListening) {
      if (!(await processStep(client))) {
        break;
      }
    }
  };
  return {
    info: async () => processInfo(),
    start: async () => {
      const client = await createRedisClient(); // Create client for this processing loop
      logApp.info('[STREAM] Starting streaming processor');
      processingLoopPromise = processingLoop(client);
    },
    shutdown: async () => {
      logApp.info('[STREAM] Shutdown streaming processor');
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
    let lastEventId;
    if (results && results.length > 0) {
      await processStreamResult(results, callback);
      const lastResult = R.last(results);
      lastEventId = R.head(lastResult);
    } else {
      const streamInfo = await fetchStreamInfo();
      lastEventId = streamInfo.lastEventId;
    }
    await client.disconnect();
    return { lastEventId };
  });
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
