import { describe, expect, it } from 'vitest';
import { s3Dependency } from '../../../src/database/raw-file-storage';
import { buildErrorScope } from '../../../src/config/error-origin';

const s3Failure = (name: string, httpStatusCode: number, fault: 'client' | 'server') => {
  return Object.assign(new Error(name), { name, $fault: fault, $metadata: { httpStatusCode } });
};

describe('S3 error classification', () => {
  it('should classify an unreachable storage as infra', () => {
    const refused = Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:9000'), { code: 'ECONNREFUSED' });
    expect(buildErrorScope(s3Dependency.classify(refused, { operation: 'upload' }), 'catalog')).toEqual({
      origin: 'infra', dependency: 's3', module: 'catalog', entry_module: 'catalog',
    });
    const timeout = Object.assign(new Error('socket timed out'), { name: 'TimeoutError' });
    expect(buildErrorScope(s3Dependency.classify(timeout, { operation: 'upload' })).origin).toBe('infra');
  });

  it('should classify a failing or throttling storage as infra', () => {
    expect(buildErrorScope(s3Dependency.classify(s3Failure('InternalError', 500, 'server'), { operation: 'list' })).origin).toBe('infra');
    expect(buildErrorScope(s3Dependency.classify(s3Failure('SlowDown', 503, 'server'), { operation: 'list' })).origin).toBe('infra');
    expect(buildErrorScope(s3Dependency.classify(s3Failure('TooManyRequests', 429, 'client'), { operation: 'list' })).origin).toBe('infra');
  });

  it('should leave a rejected request to the calling module', () => {
    const rejected = s3Failure('InvalidArgument', 400, 'client');
    const classified = s3Dependency.classify(rejected, { operation: 'upload' });
    expect(classified).toBe(rejected);
    expect(buildErrorScope(classified, 'catalog')).toEqual({ origin: 'code', module: 'catalog', entry_module: 'catalog' });
  });

  it('should attribute a bug in the client or the SDK to core', () => {
    const bug = new TypeError('Cannot read properties of undefined');
    expect(buildErrorScope(s3Dependency.classify(bug, { operation: 'upload' }), 'catalog')).toEqual({ origin: 'code', module: 'core', entry_module: 'catalog' });
  });
});
