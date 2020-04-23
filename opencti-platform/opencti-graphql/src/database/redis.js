import Redis from 'ioredis';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { assoc, isEmpty, map } from 'ramda';
import conf, { logger } from '../config/conf';

const redisOptions = {
  lazyConnect: true,
  port: conf.get('redis:port'),
  host: conf.get('redis:hostname'),
  password: conf.get('redis:password'),
  retryStrategy: (times) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 2,
};

let client;
export const initRedisClient = async () => {
  client = client || new Redis(redisOptions);
  if (client.status !== 'ready') {
    await client.connect();
  }
  client.on('error', (error) => {
    /* istanbul ignore next */
    logger.error('[REDIS] An error occurred on redis > ', error);
  });
  return true;
};

export const pubsub = new RedisPubSub({
  publisher: new Redis(redisOptions),
  subscriber: new Redis(redisOptions),
});

export const redisIsAlive = async () => {
  if (client.status !== 'ready') {
    /* istanbul ignore next */
    throw new Error('redis seems down');
  }
  return true;
};

export const getRedisVersion = () => {
  return client.serverInfo.redis_version;
};

/* istanbul ignore next */
export const notify = (topic, instance, user, context) => {
  pubsub.publish(topic, { instance, user, context });
  return instance;
};

/**
 * Set the user edition context in redis
 * @param instanceId
 * @param user
 * @param input
 */
export const setEditContext = async (user, instanceId, input) => {
  const data = assoc('name', user.user_email, input);
  return client.set(
    `edit:${instanceId}:${user.id}`,
    JSON.stringify(data),
    'ex',
    5 * 60 // Key will be remove if user is not active during 5 minutes
  );
};

/**
 * Fetch all users status for an edition context
 * @param instanceId
 * @returns {Promise<any>}
 */
export const fetchEditContext = (instanceId) => {
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
        const elements = map((d) => JSON.parse(d), data);
        resolve(elements);
      });
    });
  });
};

/**
 * Delete the user context for a specific edition
 * @param user the user
 * @param instanceId
 * @returns {*}
 */
export const delEditContext = (user, instanceId) => {
  return client.del(`edit:${instanceId}:${user.id}`);
};

/**
 * Delete the user context
 * @param user the user
 * @returns {Promise<>}
 */
export const delUserContext = (user) => {
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
      if (!isEmpty(keys)) {
        client.del(keys);
      }
      resolve();
    });
  });
};

// region cache for access token
export const getAccessCache = async (tokenUUID) => {
  const data = await client.get(tokenUUID);
  return data && JSON.parse(data);
};
export const storeAccessCache = async (tokenUUID, access) => {
  const val = JSON.stringify(access);
  await client.set(tokenUUID, val, 'ex', 90);
  return access;
};
export const clearAccessCache = async (tokenUUID) => {
  await client.del(tokenUUID);
};
// endregion
