import { describe, expect, it } from 'vitest';
import { redisDependency, wrapRedisError } from '../../../src/database/redis';
import { buildErrorScope } from '../../../src/config/error-origin';
import { DATABASE_ERROR } from '../../../src/config/errors';

const replyError = (message: string) => Object.assign(new Error(message), { name: 'ReplyError' });

describe('Redis error classification (RFC 0006)', () => {
  it('should treat an unreachable or closed Redis as unavailable', () => {
    expect(buildErrorScope(redisDependency.classify(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }))).origin).toBe('infra');
    expect(buildErrorScope(redisDependency.classify(new Error('Connection is closed.'))).origin).toBe('infra');
    expect(buildErrorScope(redisDependency.classify(Object.assign(new Error('Reached the max retries per request limit'), { name: 'MaxRetriesPerRequestError' }))).origin).toBe('infra');
  });

  it('should treat a server that cannot serve right now as unavailable', () => {
    ['LOADING Redis is loading the dataset in memory', 'READONLY You can\'t write against a read only replica.', 'OOM command not allowed when used memory > \'maxmemory\'.', 'CLUSTERDOWN The cluster is down']
      .forEach((message) => expect(buildErrorScope(redisDependency.classify(replyError(message))).origin).toBe('infra'));
  });

  it('should treat a command Redis rejects as a code fault', () => {
    const wrongType = replyError('WRONGTYPE Operation against a key holding the wrong kind of value');
    expect(redisDependency.classify(wrongType)).toBe(wrongType);
    expect(buildErrorScope(wrapRedisError('Redis transaction error', wrongType)).origin).toBe('code');
  });

  it('should keep DATABASE_ERROR for an unavailable Redis, classified as infra', () => {
    const wrapped: any = wrapRedisError('Redis transaction error', new Error('Connection is closed.'));
    expect(wrapped.extensions.code).toBe(DATABASE_ERROR);
    expect(buildErrorScope(wrapped, 'catalog')).toEqual({ origin: 'infra', dependency: 'redis', module: 'catalog', entry_module: 'catalog' });
  });
});
