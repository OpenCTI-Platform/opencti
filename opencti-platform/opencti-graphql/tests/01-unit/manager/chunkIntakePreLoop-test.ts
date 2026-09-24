import { describe, expect, it } from 'vitest';
import { PreLoopGate } from '../../../src/manager/chunkIntakePreLoop';

const settle = () => new Promise<void>((resolve) => {
  setTimeout(resolve, 0);
});

const gateWithClock = (overrides: Partial<ConstructorParameters<typeof PreLoopGate>[0]> = {}) => {
  let clock = 100_000;
  const changes: [number, 'up' | 'down'][] = [];
  const gate = new PreLoopGate({
    initial: 32,
    min: 8,
    max: 512,
    adaptive: true,
    increaseRatio: 0.25,
    quietMs: 10_000,
    now: () => clock,
    onLimitChange: (limit, direction) => changes.push([limit, direction]),
    ...overrides,
  });
  const advance = (ms: number) => {
    clock += ms;
  };
  return { gate, changes, advance };
};

describe('chunk intake pre-loop gate', () => {
  it('hands permits without waiting below the limit and pauses at it', async () => {
    const { gate } = gateWithClock({ initial: 2, min: 1 });
    expect(await gate.acquire()).toBe(false);
    expect(await gate.acquire()).toBe(false);
    let third: boolean | null = null;
    const pending = gate.acquire().then((waited) => {
      third = waited;
    });
    await settle();
    expect(third).toBeNull();
    expect(gate.waiting()).toBe(1);
    gate.release();
    await pending;
    expect(third).toBe(true);
    expect(gate.inFlight()).toBe(2);
  });

  it('is transparent when disabled (initial 0)', async () => {
    const { gate, changes } = gateWithClock({ initial: 0 });
    expect(gate.enabled()).toBe(false);
    expect(await gate.acquire()).toBe(false);
    expect(await gate.acquire()).toBe(false);
    gate.tick();
    expect(changes).toEqual([]);
  });

  it('grows while operations are paced and the engine is quiet, and wakes the waiters', async () => {
    const { gate, changes } = gateWithClock({ initial: 4, min: 2, max: 512 });
    for (let i = 0; i < 4; i += 1) await gate.acquire();
    const waiters = [gate.acquire(), gate.acquire()];
    await settle();
    expect(gate.waiting()).toBe(2);
    gate.tick(); // paced 2, no error ever: +25% of 4 = 1
    expect(gate.currentLimit()).toBe(5);
    expect(changes).toEqual([[5, 'up']]);
    await settle();
    expect(gate.waiting()).toBe(1); // one permit appeared, one waiter served
    gate.tick(); // paced is counted at acquire time: nothing new this window, hold
    expect(gate.currentLimit()).toBe(5);
    gate.release();
    await Promise.all(waiters);
  });

  it('holds when nothing was paced', () => {
    const { gate, changes } = gateWithClock({ initial: 32 });
    gate.tick();
    gate.tick();
    expect(gate.currentLimit()).toBe(32);
    expect(changes).toEqual([]);
  });

  it('halves on engine errors, keeps halving while they last, floors at min', () => {
    const { gate, changes } = gateWithClock({ initial: 64, min: 8 });
    gate.onEngineError();
    gate.tick();
    expect(gate.currentLimit()).toBe(32);
    gate.tick(); // quiet tick: no further decrease, no increase (nothing paced)
    expect(gate.currentLimit()).toBe(32);
    gate.onEngineError();
    gate.onEngineError();
    gate.tick();
    expect(gate.currentLimit()).toBe(16);
    gate.onEngineError();
    gate.tick();
    gate.onEngineError();
    gate.tick();
    gate.onEngineError();
    gate.tick();
    expect(gate.currentLimit()).toBe(8);
    expect(changes).toEqual([[32, 'down'], [16, 'down'], [8, 'down']]);
  });

  it('does not grow again before the quiet window has passed', async () => {
    const { gate, advance } = gateWithClock({ initial: 8, min: 4, quietMs: 10_000 });
    for (let i = 0; i < 8; i += 1) await gate.acquire();
    gate.onEngineError();
    gate.tick();
    expect(gate.currentLimit()).toBe(4);
    const waiter = gate.acquire(); // paced
    await settle();
    advance(5_000);
    gate.tick();
    expect(gate.currentLimit()).toBe(4); // error 5 s ago: hold
    void gate.acquire(); // paced again
    await settle();
    advance(6_000);
    gate.tick();
    expect(gate.currentLimit()).toBe(5); // 11 s quiet: grow
    for (let i = 0; i < 8; i += 1) gate.release();
    await waiter;
  });

  it('caps the growth at max and pins the limit when not adaptive', async () => {
    const { gate: capped, changes } = gateWithClock({ initial: 500, max: 512 });
    for (let i = 0; i < 500; i += 1) await capped.acquire();
    void capped.acquire();
    await settle();
    capped.tick();
    expect(capped.currentLimit()).toBe(512);
    void capped.acquire();
    await settle();
    capped.tick();
    expect(capped.currentLimit()).toBe(512);
    expect(changes).toEqual([[512, 'up']]);
    const { gate: fixed, changes: fixedChanges } = gateWithClock({ initial: 32, adaptive: false });
    for (let i = 0; i < 32; i += 1) await fixed.acquire();
    void fixed.acquire();
    await settle();
    fixed.tick();
    fixed.onEngineError();
    fixed.tick();
    expect(fixed.currentLimit()).toBe(32);
    expect(fixedChanges).toEqual([]);
  });
});
