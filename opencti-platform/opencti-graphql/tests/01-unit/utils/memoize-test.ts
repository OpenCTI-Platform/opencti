import { describe, it, expect, vi } from 'vitest';
import { memoizeAsync } from '../../../src/utils/memoize';

describe('memoizeAsync', () => {
  it('should compute a value once and share it between calls', async () => {
    const fun = vi.fn(async () => 42);
    const memoized = memoizeAsync(fun);
    expect(await Promise.all([memoized(), memoized()])).toEqual([42, 42]);
    expect(await memoized()).toEqual(42);
    expect(fun).toHaveBeenCalledTimes(1);
  });

  it('should compute again after a failure', async () => {
    const fun = vi.fn()
      .mockRejectedValueOnce(new Error('unreadable'))
      .mockResolvedValue('etag');
    const memoized = memoizeAsync(fun);
    await expect(memoized()).rejects.toThrow('unreadable');
    expect(await memoized()).toEqual('etag');
    expect(await memoized()).toEqual('etag');
    expect(fun).toHaveBeenCalledTimes(2);
  });

  it('should keep one value per key', async () => {
    const fun = vi.fn(async (path: string) => `hash-${path}`);
    const memoized = memoizeAsync(fun, (path) => path);
    expect(await memoized('a')).toEqual('hash-a');
    expect(await memoized('b')).toEqual('hash-b');
    expect(await memoized('a')).toEqual('hash-a');
    expect(fun).toHaveBeenCalledTimes(2);
  });
});
