import { afterEach, describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { getClientBase } from '../../../../src/database/redis';
import { createLandscapeClusterSlots } from '../../../../src/modules/timeMachine/landscapeDiff-domain';

const LIMITS = { maxPerUser: 1, maxTotal: 2, staleSeconds: 120 };

const fakeClock = () => {
  let time = 1_000_000;
  const advance = (seconds: number) => {
    time += seconds * 1000;
  };
  return { now: () => time, advance };
};

describe('Landscape diff slots of the platform', () => {
  // A key of its own, so the computations of the other tests are not counted
  const key = `landscape_diff_slots_test_${uuid()}`;

  afterEach(async () => {
    await getClientBase().del(key);
  });

  it('applies the per user and total limits to every node', async () => {
    const clock = fakeClock();
    const nodeA = createLandscapeClusterSlots(key, LIMITS, clock.now);
    const nodeB = createLandscapeClusterSlots(key, LIMITS, clock.now);
    expect(await nodeA.reserve('run-1', 'user-1')).toBe(true);
    // The same user on another node
    expect(await nodeB.reserve('run-2', 'user-1')).toBe(false);
    expect(await nodeB.reserve('run-3', 'user-2')).toBe(true);
    // The platform total is reached
    expect(await nodeA.reserve('run-4', 'user-3')).toBe(false);
    await nodeA.release('run-1', 'user-1');
    expect(await nodeB.reserve('run-5', 'user-1')).toBe(true);
  });

  it('frees the slot of a computation that stopped reporting progress and stops it if it resumes', async () => {
    const clock = fakeClock();
    const nodeA = createLandscapeClusterSlots(key, LIMITS, clock.now);
    const nodeB = createLandscapeClusterSlots(key, LIMITS, clock.now);
    expect(await nodeA.reserve('run-1', 'user-1')).toBe(true);
    clock.advance(60);
    // A progress extends the lease for another period
    expect(await nodeA.extend('run-1', 'user-1')).toBe(true);
    clock.advance(100);
    expect(await nodeB.reserve('run-2', 'user-1')).toBe(false);
    clock.advance(30);
    // 130 seconds without progress: the lease expired, its slot is free
    expect(await nodeA.extend('run-1', 'user-1')).toBe(false);
    expect(await nodeB.reserve('run-2', 'user-1')).toBe(true);
    expect(await nodeA.extend('run-1', 'user-1')).toBe(false);
  });
});
