// Initialization of the benchmark platform: the global setup does the work when INIT_TEST_PLATFORM=true.
import { describe, expect, it } from 'vitest';
import { isPlatformAlive } from '../../utils/testQuery';

describe('Benchmark platform', () => {
  it('is initialized', async () => {
    expect(await isPlatformAlive()).toBe(true);
  });
});
