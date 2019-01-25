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
 * @param user the user
 * @param instanceId
 * @returns {*}
 */
export const delEditContext = (user, instanceId) =>
  client.del(`edit:${instanceId}:${user.id}`);

/**
 * Delete the user context
 * @param user the user
 * @returns {Promise<>}
 */
export const delUserContext = user =>
  new Promise((resolve, reject) => {
    const stream = client.scanStream({
      match: `*:*:${user.id}`,
      count: 100
    });
    const keys = [];
    stream.on('data', resultKeys => {
      for (let index = 0; index < resultKeys.length; index += 1) {
        keys.push(resultKeys[index]);
      }
    });
    stream.on('error', error => {
      reject(error);
    });
    stream.on('end', () => {
      console.log('deleting user redis keys', keys);
      client.del(keys);
      resolve();
    });
  });

/**
 * Set the user edition context in redis
 * @param instanceId
 * @param user
 * @param input
 */
export const setEditContext = (user, instanceId, input) => {
  const data = assoc('name', user.email, input);
  client.set(
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
