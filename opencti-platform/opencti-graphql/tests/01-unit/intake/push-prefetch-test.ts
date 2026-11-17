import { describe, expect, it } from 'vitest';
import { isOversized, prefetchForSize, retargetPrefetch } from '../../../src/intake/workerless/push-prefetch';

const MB = 1024 * 1024;
const options = { initial: 25, bytes: 32 * MB, max: 600 };

describe('push prefetch by bytes (task 0040)', () => {
  it('should hold about the byte budget per queue, within 1 and the bound', () => {
    expect(prefetchForSize(48 * 1024, options)).toBe(600); // one object per message: bounded
    expect(prefetchForSize(MB, options)).toBe(32);
    expect(prefetchForSize(200 * MB, options)).toBe(1); // a whole giant bundle: one at a time
    expect(prefetchForSize(0, options)).toBe(600);
  });

  it('should change the prefetch only when off by a factor 2 or more', () => {
    expect(retargetPrefetch(25, 48 * 1024, options)).toBe(600);
    expect(retargetPrefetch(25, 200 * MB, options)).toBe(1);
    expect(retargetPrefetch(25, MB, options)).toBe(null); // 32: kept at 25
    expect(retargetPrefetch(600, 64 * 1024, options)).toBe(null); // 512: kept at 600
    expect(retargetPrefetch(3, 32 * MB, options)).toBe(1);
    expect(retargetPrefetch(1, 32 * MB, options)).toBe(null);
  });

  it('should keep the prefetch fixed without a byte budget or a known size', () => {
    expect(retargetPrefetch(25, 48 * 1024, { ...options, bytes: 0 })).toBe(null);
    expect(retargetPrefetch(25, 0, options)).toBe(null);
    expect(retargetPrefetch(25, Number.NaN, options)).toBe(null);
  });

  it('should flag a delivered message the current credit cannot hold within twice the budget', () => {
    expect(isOversized(150 * MB, 600, options)).toBe(true);
    expect(isOversized(150 * MB, 1, options)).toBe(true); // already at 1: retargetPrefetch keeps it
    expect(retargetPrefetch(1, 150 * MB, options)).toBe(null);
    expect(isOversized(64 * 1024, 600, options)).toBe(false);
    expect(isOversized(150 * MB, 600, { ...options, bytes: 0 })).toBe(false);
  });
});
