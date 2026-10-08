import { describe, expect, it } from 'vitest';
import { defineDependencyClient } from '../../../src/database/dependency-client';
import { buildErrorScope } from '../../../src/config/error-origin';

const unavailable = Object.assign(new Error('service down'), { unavailable: true });
const redis = defineDependencyClient({
  dependency: 'redis',
  isUnavailable: (err: any) => err?.unavailable === true,
  unavailableMessage: 'Redis is unavailable',
});

describe('dependency client', () => {
  it('should turn an unavailable service into an infra error naming the dependency and the operation', async () => {
    const error: any = await redis.call('push_log', async () => {
      throw unavailable;
    }).catch((e: unknown) => e);
    expect(buildErrorScope(error, 'catalog')).toEqual({ origin: 'infra', dependency: 'redis', module: 'catalog', entry_module: 'catalog' });
    expect(error.message).toBe('Redis is unavailable');
    expect(error.extensions.data).toMatchObject({ dependency: 'redis', operation: 'push_log', cause: unavailable });
  });

  it('should let the caller name the failure', () => {
    const error: any = redis.classify(unavailable, { reason: 'Fail to push auth log', userId: 'u1' });
    expect(error.message).toBe('Fail to push auth log');
    expect(error.extensions.data).toMatchObject({ userId: 'u1' });
  });

  it('should attribute a bug in the client or its library to core', () => {
    expect(buildErrorScope(redis.classify(new TypeError('x is undefined')), 'catalog').module).toBe('core');
  });

  it('should leave a rejected request untouched', async () => {
    const rejected = new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
    await expect(redis.call('push_log', async () => {
      throw rejected;
    })).rejects.toBe(rejected);
  });

  it('should return the result untouched', async () => {
    await expect(redis.call('get', async () => 'value')).resolves.toBe('value');
  });
});
