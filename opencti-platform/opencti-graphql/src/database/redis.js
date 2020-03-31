import Redis from 'ioredis';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { assoc, isEmpty, map } from 'ramda';
import conf, { isAppRealTime, logger } from '../config/conf';

const redisOptions = {
  port: conf.get('redis:port'),
  host: conf.get('redis:hostname'),
  password: conf.get('redis:password'),
  retryStrategy: (times) => Math.min(times * 50, 2000),
  maxRetriesPerRequest: 2,
};

export const pubsub = isAppRealTime
  ? new RedisPubSub({
      publisher: new Redis(redisOptions),
      subscriber: new Redis(redisOptions),
    })
  : null;

const client = isAppRealTime && new Redis(redisOptions);
if (client) {
  client.on('error', (error) => {
    logger.error('[REDIS] An error occurred on redis > ', error);
  });
}
const isActive = () => client && client.status === 'ready';

export const getRedisVersion = () => {
  if (isActive()) return client.serverInfo.redis_version;
  return 'Disconnected';
};

export const notify = (topic, instance, user, context) => {
  if (pubsub) pubsub.publish(topic, { instance, user, context });
  return instance;
};

/**
 * Delete the user context for a specific edition
 * @param user the user
 * @param instanceId
 * @returns {*}
 */
export const delEditContext = (user, instanceId) => {
  return isActive() && client.del(`edit:${instanceId}:${user.id}`);
};

/**
 * Delete the user context
 * @param user the user
 * @returns {Promise<>}
 */
export const delUserContext = (user) => {
  return isActive()
    ? new Promise((resolve, reject) => {
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
          reject(error);
        });
        stream.on('end', () => {
          if (!isEmpty(keys)) {
            client.del(keys);
          }
          resolve();
        });
      })
    : null;
};

/**
 * Set the user edition context in redis
 * @param instanceId
 * @param user
 * @param input
 */
export const setEditContext = (user, instanceId, input) => {
  const data = assoc('name', user.user_email, input);
  if (isActive()) {
    client.set(
      `edit:${instanceId}:${user.id}`,
      JSON.stringify(data),
      'ex',
      5 * 60 // Key will be remove if user is not active during 5 minutes
    );
  }
};

/**
 * Fetch all users status for an edition context
 * @param instanceId
 * @returns {Promise<any>}
 */
export const fetchEditContext = (instanceId) => {
  return isActive()
    ? new Promise((resolve, reject) => {
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
          reject(error);
        });
        stream.on('end', () => {
          Promise.all(elementsPromise).then((data) => {
            const elements = map((d) => JSON.parse(d), data);
            resolve(elements);
          });
        });
      })
    : Promise.resolve([]);
};

// region cache for access token
export const getAccessCache = async (tokenUUID) => {
  if (isActive()) {
    const data = await client.get(tokenUUID);
    return data && JSON.parse(data);
  }
  return undefined;
};
export const storeAccessCache = async (tokenUUID, access) => {
  if (isActive()) {
    const val = JSON.stringify(access);
    await client.set(tokenUUID, val, 'ex', 90);
    return access;
  }
  return undefined;
};
export const clearAccessCache = async (tokenUUID) => {
  if (isActive()) {
    await client.del(tokenUUID);
  }
};
// endregion
