import Redis from 'ioredis';
import { RedisPubSub } from 'graphql-redis-subscriptions';
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
export default client;
