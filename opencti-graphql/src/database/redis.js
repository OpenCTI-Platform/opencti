import * as redis from 'redis';
import conf from '../config/conf';

const client = redis.createClient({
  host: conf.get('redis:host'),
  port: conf.get('redis:port'),
  password: conf.get('redis:password')
});

client.on('error', err => {
  console.log(`Error ${err}`);
});

export default client;
