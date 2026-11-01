import { describe, expect, it, vi } from 'vitest';
import { createSharedCredentialProvider } from '../../../src/utils/awsCredentialProvider';

type Credentials = { accessKeyId: string; secretAccessKey: string; expiration?: Date };

// Stand-in for an AWS SDK memoized provider: resolves once, then serves the cached credentials
const buildMemoizedProvider = (resolve: () => Promise<Credentials>) => {
  let cached: Promise<Credentials> | undefined;
  return () => {
    if (!cached) {
      cached = resolve();
    }
    return cached;
  };
};

describe('createSharedCredentialProvider', () => {
  it('creates the provider lazily, once, whatever the number of calls', async () => {
    const resolve = vi.fn(async () => ({ accessKeyId: 'AKIA', secretAccessKey: 'secret' }));
    const factory = vi.fn(() => buildMemoizedProvider(resolve));
    const getCredentials = createSharedCredentialProvider(factory);
    expect(factory).not.toHaveBeenCalled();
    for (let i = 0; i < 100; i += 1) {
      await getCredentials();
    }
    expect(factory).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledTimes(1);
  });

  it('shares one resolution between concurrent callers', async () => {
    const resolve = vi.fn(async () => ({ accessKeyId: 'AKIA', secretAccessKey: 'secret' }));
    const getCredentials = createSharedCredentialProvider(() => buildMemoizedProvider(resolve));
    const results = await Promise.all(Array.from({ length: 20 }, () => getCredentials()));
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(new Set(results).size).toBe(1);
    expect(results[0]).toEqual({ accessKeyId: 'AKIA', secretAccessKey: 'secret' });
  });

  it('returns what the underlying provider returns on each call', async () => {
    let counter = 0;
    const getCredentials = createSharedCredentialProvider(() => async () => {
      counter += 1;
      return { accessKeyId: `key-${counter}`, secretAccessKey: 'secret' };
    });
    expect((await getCredentials()).accessKeyId).toBe('key-1');
    expect((await getCredentials()).accessKeyId).toBe('key-2');
  });
});
