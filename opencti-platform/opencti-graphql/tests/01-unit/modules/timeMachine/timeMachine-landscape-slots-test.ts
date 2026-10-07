import { describe, expect, it } from 'vitest';
import { createLandscapeRunSlots } from '../../../../src/modules/timeMachine/landscapeDiff-domain';

const LIMITS = { maxPerUser: 1, maxTotal: 2, staleSeconds: 120 };

const fakeClock = () => {
  let time = 1_000_000;
  const advance = (seconds: number) => {
    time += seconds * 1000;
  };
  return { now: () => time, advance };
};

describe('Landscape diff concurrency slots', () => {
  it('should enforce the per user and global limits', () => {
    const clock = fakeClock();
    const slots = createLandscapeRunSlots(LIMITS, clock.now);
    expect(slots.reserve('run-1', 'user-a')).not.toBeNull();
    expect(slots.reserve('run-2', 'user-a')).toBeNull();
    expect(slots.reserve('run-3', 'user-b')).not.toBeNull();
    expect(slots.reserve('run-4', 'user-c')).toBeNull();
    expect(slots.size()).toEqual(2);
  });

  it('should release a slot once, whatever the number of releases', () => {
    const clock = fakeClock();
    const slots = createLandscapeRunSlots(LIMITS, clock.now);
    slots.reserve('run-1', 'user-a');
    slots.reserve('run-2', 'user-b');
    slots.release('run-1');
    slots.release('run-1');
    expect(slots.size()).toEqual(1);
    expect(slots.reserve('run-3', 'user-a')).not.toBeNull();
  });

  it('should abort and free the slot of a computation without progress for the stale delay', () => {
    const clock = fakeClock();
    const slots = createLandscapeRunSlots(LIMITS, clock.now);
    const hung = slots.reserve('run-1', 'user-a');
    clock.advance(LIMITS.staleSeconds + 1);
    // The next request of the user is not refused because of the hung computation
    const retry = slots.reserve('run-2', 'user-a');
    expect(retry).not.toBeNull();
    expect(hung?.controller.signal.aborted).toBe(true);
    expect((hung?.controller.signal.reason as Error).message).toEqual('Landscape diff computation was interrupted');
    expect(retry?.controller.signal.aborted).toBe(false);
    expect(slots.size()).toEqual(1);
  });

  it('should keep the slot of a computation reporting progress', () => {
    const clock = fakeClock();
    const slots = createLandscapeRunSlots(LIMITS, clock.now);
    const running = slots.reserve('run-1', 'user-a');
    clock.advance(LIMITS.staleSeconds - 10);
    slots.touch('run-1');
    clock.advance(LIMITS.staleSeconds - 10);
    expect(slots.reserve('run-2', 'user-a')).toBeNull();
    expect(running?.controller.signal.aborted).toBe(false);
  });

  it('should abort a computation released with a reason', () => {
    const clock = fakeClock();
    const slots = createLandscapeRunSlots(LIMITS, clock.now);
    const running = slots.reserve('run-1', 'user-a');
    slots.release('run-1', 'Landscape diff computation was interrupted');
    expect(running?.controller.signal.aborted).toBe(true);
    expect(slots.size()).toEqual(0);
  });
});
