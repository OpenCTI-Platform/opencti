import Redis from 'ioredis';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { assoc, map } from 'ramda';
import conf from '../config/conf';

const redisOptions = {
  port: conf.get('redis:port'), // Redis port
  host: conf.get('redis:host'), // Redis host
  password: conf.get('redis:password')
};

export const pubsub = new RedisPubSub({
  publisher: new Redis(redisOptions),
  subscriber: new Redis(redisOptions)
});

const client = new Redis(redisOptions);

/**
 * Delete the user context for a specific edition
 * @param user
 * @param instanceId
 * @returns {*}
 */
export const delEditContext = (user, instanceId) =>
  client.del(`edit:${instanceId}:${user.id}`);

/**
 * Set the user edition context in redis
 * @param instanceId
 * @param user
 * @param input
 */
export const setEditContext = (user, instanceId, input) => {
  const data = assoc('username', user.email, input);
  client.set(`edit:${instanceId}:${user.id}`, JSON.stringify(data));
};

/**
 * Fetch all users status for an edition context
 * @param instanceId
 * @returns {Promise<any>}
 */
export const fetchEditContext = instanceId =>
  new Promise((resolve, reject) => {
    const elementsPromise = [];
    const stream = client.scanStream({
      match: `edit:${instanceId}:*`,
      count: 100
    });
    stream.on('data', resultKeys => {
      for (let i = 0; i < resultKeys.length; i += 1) {
        elementsPromise.push(client.get(resultKeys[i]));
      }
    });
    stream.on('error', error => {
      reject(error);
    });
    stream.on('end', () => {
      Promise.all(elementsPromise).then(data => {
        const elements = map(d => JSON.parse(d), data);
        resolve(elements);
      });
    });
  });

export default client;
