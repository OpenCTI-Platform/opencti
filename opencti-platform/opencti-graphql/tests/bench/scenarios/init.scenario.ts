// Initialization of the benchmark platform: the global setup does the work when INIT_TEST_PLATFORM=true; the
// lock-free state of the previous platform is dropped with it.
import { describe, expect, it } from 'vitest';
import { isPlatformAlive } from '../../utils/testQuery';
import { resetLockFreeState } from '../lockfree/run';

describe('Benchmark platform', () => {
  it('is initialized', async () => {
    expect(await isPlatformAlive()).toBe(true);
    await resetLockFreeState();
  });
});
