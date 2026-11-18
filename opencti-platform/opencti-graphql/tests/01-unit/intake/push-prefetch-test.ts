import { describe, expect, it } from 'vitest';
import { heldToStart, initialPrefetch, nextPrefetch, planPrefetch, prefetchFor, type QueuePrefetchInput } from '../../../src/intake/workerless/push-prefetch';

const KB = 1024;
const MB = 1024 * KB;
const options = { initial: 25, totalBytes: 256 * MB, totalMessages: 600, max: 400 };
const queue = (name: string, input: Partial<QueuePrefetchInput> = {}): QueuePrefetchInput => ({
  queue: name, active: true, meanReadyBytes: 48 * KB, largestRecentBytes: 0, ordered: false, ...input,
});
const active = (n: number, input: Partial<QueuePrefetchInput> = {}) => Array.from({ length: n }, (_, i) => queue(`push_${i}`, input));
const prefetches = (inputs: QueuePrefetchInput[], with_ = options) => [...planPrefetch(inputs, with_).values()].map(({ prefetch }) => prefetch);

describe('push prefetch shared between the queues (task 0040)', () => {
  it('should share the message budget between the active queues, within the bound of one queue', () => {
    // small messages: the batches need messages, the bytes do not bind
    expect(prefetches(active(1))).toEqual([400]); // alone: the bound
    expect(prefetches(active(5))).toEqual(Array(5).fill(120));
    expect(prefetches(active(20))).toEqual(Array(20).fill(30)); // about the fixed 25
    expect(prefetches(active(30))).toEqual(Array(30).fill(20));
    expect([...planPrefetch(active(5), options).values()].map(({ shares }) => shares)).toEqual(Array(5).fill(5));
  });

  it('should share the byte budget: one giant message at a time', () => {
    expect(prefetches(active(1, { meanReadyBytes: 150 * MB }))).toEqual([1]);
    expect(prefetches(active(20, { meanReadyBytes: 150 * MB }))).toEqual(Array(20).fill(1));
    // 1 MB messages, 4 queues: 64 MB each, 64 messages (the message share, 150, does not bind)
    expect(prefetches(active(4, { meanReadyBytes: MB }))).toEqual(Array(4).fill(64));
  });

  it('should size a queue for the largest message delivered recently, not only the mean of the ready ones', () => {
    expect(prefetchFor(queue('push_a', { meanReadyBytes: 40 * KB, largestRecentBytes: 2 * MB }), 1, options)).toBe(128);
    expect(prefetchFor(queue('push_a', { meanReadyBytes: 2 * MB, largestRecentBytes: 40 * KB }), 1, options)).toBe(128);
    expect(prefetchFor(queue('push_a', { meanReadyBytes: 0, largestRecentBytes: 2 * MB }), 1, options)).toBe(128);
  });

  it('should not raise a queue whose message size is unknown', () => {
    expect(prefetchFor(queue('push_a', { meanReadyBytes: 0, largestRecentBytes: 0 }), 1, options)).toBe(25);
    expect(prefetchFor(queue('push_a', { meanReadyBytes: Number.NaN, largestRecentBytes: Number.NaN }), 1, options)).toBe(25);
    expect(prefetchFor(queue('push_a', { meanReadyBytes: -5, largestRecentBytes: 0 }), 1, options)).toBe(25);
  });

  it('should keep a queue with nothing to do sized for the whole set of queues', () => {
    const plan = planPrefetch([queue('push_busy'), queue('push_idle', { active: false })], options);
    expect(plan.get('push_busy')).toEqual({ prefetch: 400, shares: 1 }); // the only active one
    expect(plan.get('push_idle')).toEqual({ prefetch: 25, shares: 2 }); // min(start value, 600 / 2)
    // idle among 30: its share of the whole set (600 / 30), below the start value
    expect(planPrefetch(active(30, { active: false }), options).get('push_0')).toEqual({ prefetch: 20, shares: 30 });
  });

  it('should keep an ordered queue at the start value', () => {
    expect(planPrefetch([queue('push_events', { ordered: true })], options).get('push_events')?.prefetch).toBe(25);
  });

  it('should keep every queue at the start value when a budget is 0', () => {
    expect(prefetches(active(1), { ...options, totalBytes: 0 })).toEqual([25]);
    expect(prefetches(active(1), { ...options, totalMessages: 0 })).toEqual([25]);
  });

  it('should never plan 0 (unlimited for RabbitMQ) nor above the bound or the 16-bit limit', () => {
    expect(initialPrefetch({ ...options, initial: 600 })).toBe(400); // start value above the bound
    expect(initialPrefetch({ ...options, initial: 0 })).toBe(1);
    expect(initialPrefetch({ ...options, initial: Number.NaN })).toBe(1);
    expect(initialPrefetch({ ...options, initial: 25, max: 100000 })).toBe(25);
    expect(prefetchFor(queue('push_a', { meanReadyBytes: 1 }), 1, { ...options, totalMessages: 1e9, totalBytes: 1e12, max: 100000 })).toBe(65535);
    expect(prefetchFor(queue('push_a', { meanReadyBytes: 1024 * MB }), 1, options)).toBe(1);
  });

  it('should raise at most x2 at a time, once the plan is a quarter and 2 above', () => {
    expect(nextPrefetch(25, 400, 25)).toBe(50);
    expect(nextPrefetch(200, 400, 25)).toBe(400);
    expect(nextPrefetch(40, 50, 25)).toBe(50);
    expect(nextPrefetch(40, 49, 25)).toBe(null);
    expect(nextPrefetch(25, 25, 25)).toBe(null);
    // giant messages: no 2 <-> 3 swing, 1 -> 2 and 2 -> 3 wait for a plan 2 above
    expect(nextPrefetch(2, 3, 25)).toBe(null);
    expect(nextPrefetch(1, 2, 25)).toBe(null);
    expect(nextPrefetch(1, 3, 25)).toBe(2);
    expect(nextPrefetch(2, 4, 25)).toBe(4);
  });

  it('should lower at once to the plan, once it is under 3/4 of the prefetch', () => {
    expect(nextPrefetch(400, 2, 25)).toBe(2);
    expect(nextPrefetch(400, 299, 25)).toBe(299);
    expect(nextPrefetch(400, 300, 25)).toBe(null);
    expect(nextPrefetch(4, 2, 25)).toBe(2);
    expect(nextPrefetch(2, 1, 25)).toBe(1);
    expect(nextPrefetch(3, 2, 25)).toBe(2);
  });

  it('should lower at once a queue held to the start value and above it, even inside the 3/4 band', () => {
    expect(nextPrefetch(33, 25, 25, true)).toBe(25);
    expect(nextPrefetch(26, 25, 25, true)).toBe(25);
    // idle among 25 queues or more: its plan is under the start value (600 / 25 = 24)
    expect(nextPrefetch(32, 24, 25, true)).toBe(24);
    // no ratchet under the start value, and an active queue keeps the band (no 25 <-> 32 swing)
    expect(nextPrefetch(24, 23, 25, true)).toBe(null);
    expect(nextPrefetch(25, 24, 25, true)).toBe(null);
    expect(nextPrefetch(32, 25, 25, false)).toBe(null);
    expect(nextPrefetch(32, 25, 25)).toBe(null);
  });

  it('should hold an ordered or idle queue to the start value, not an active one', () => {
    expect(heldToStart(queue('push_a', { ordered: true }))).toBe(true);
    expect(heldToStart(queue('push_a', { active: false }))).toBe(true);
    expect(heldToStart(queue('push_a'))).toBe(false);
  });

  it('should hold an active queue within 4/3 of its byte share once applied', () => {
    // 1.2 MB messages alone: plan 213; from any prefetch above it, what is kept or applied holds at most 4/3 of the
    // byte budget (x2 hysteresis would have kept 400: 480 MB)
    const planned = prefetchFor(queue('push_a', { meanReadyBytes: 1.2 * MB }), 1, options);
    expect(planned).toBe(213);
    for (let current = planned + 1; current <= options.max; current += 1) {
      const held = nextPrefetch(current, planned, options.initial) ?? current;
      expect(held * 1.2 * MB).toBeLessThanOrEqual((4 / 3) * options.totalBytes);
    }
    expect(nextPrefetch(280, planned, options.initial)).toBe(null); // just inside the band: kept
  });
});
