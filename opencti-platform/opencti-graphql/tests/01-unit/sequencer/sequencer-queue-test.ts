import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SequencerQueue, SourceLane } from '../../../src/database/sequencer/sequencer-queue';
import { buildIntent } from '../../../src/database/sequencer/sequencer-intent';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const intentFrom = (source: string, name: string) => buildIntent({
  kind: 'entity',
  type: 'Malware',
  input: { name },
  user: { id: 'u', origin: { applicant_id: source } } as unknown as AuthUser,
  context: {} as unknown as AuthContext,
  opts: {},
  candidateIds: [],
  apply: async () => name,
});

const savedIntents = SEQUENCER_CONFIG.queueMaxIntents;
const savedBytes = SEQUENCER_CONFIG.queueMaxBytes;

describe('sequencer queue (plan 0009 B4)', () => {
  beforeAll(() => {
    SEQUENCER_CONFIG.queueMaxIntents = 4;
    SEQUENCER_CONFIG.queueMaxBytes = 1024 * 1024;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.queueMaxIntents = savedIntents;
    SEQUENCER_CONFIG.queueMaxBytes = savedBytes;
  });

  it('indexes queued candidate ids, refcounted across intents (s9.8.3 queue index)', async () => {
    const queue = new SequencerQueue();
    const a = buildIntent({
      kind: 'entity',
      type: 'Malware',
      input: { name: 'a' },
      user: { id: 'u', origin: { applicant_id: 'c1' } } as unknown as AuthUser,
      context: {} as unknown as AuthContext,
      opts: {},
      candidateIds: ['malware--x', 'malware--alias'],
      apply: async () => 'a',
    });
    const b = buildIntent({
      kind: 'entity',
      type: 'Malware',
      input: { name: 'b' },
      user: { id: 'u', origin: { applicant_id: 'c2' } } as unknown as AuthUser,
      context: {} as unknown as AuthContext,
      opts: {},
      candidateIds: ['malware--x'],
      apply: async () => 'b',
    });
    await queue.put(a);
    await queue.put(b);
    expect(queue.hasCandidate('malware--x')).toBe(true);
    expect(queue.hasCandidate('malware--alias')).toBe(true);
    expect(queue.hasCandidate('malware--other')).toBe(false);
    queue.tryPop(); // pops a (c1 first in the ring)
    expect(queue.hasCandidate('malware--x')).toBe(true); // still asserted by b
    expect(queue.hasCandidate('malware--alias')).toBe(false);
    queue.tryPop();
    expect(queue.hasCandidate('malware--x')).toBe(false);
  });

  it('dequeues round-robin by source', async () => {
    const q = new SequencerQueue();
    await q.put(intentFrom('connA', 'a1'));
    await q.put(intentFrom('connA', 'a2'));
    await q.put(intentFrom('connA', 'a3'));
    await q.put(intentFrom('connB', 'b1'));
    const order = [];
    order.push((await q.take()).input.name);
    order.push((await q.take()).input.name);
    order.push((await q.take()).input.name);
    order.push((await q.take()).input.name);
    // one flooding connector (A) cannot starve B: B interleaves despite arriving last
    expect(order).toEqual(['a1', 'b1', 'a2', 'a3']);
    expect(q.size()).toBe(0);
  });

  it('blocks put when full and releases on take (backpressure)', async () => {
    const q = new SequencerQueue();
    for (let i = 0; i < 4; i += 1) await q.put(intentFrom('connA', `a${i}`));
    let entered = false;
    const pending = q.put(intentFrom('connB', 'b0')).then(() => {
      entered = true;
    });
    await new Promise((r) => { setTimeout(r, 10); });
    expect(entered).toBe(false); // still waiting for a slot
    await q.take();
    await pending;
    expect(entered).toBe(true);
    expect(q.size()).toBe(4);
  });

  it('take awaits until an intent arrives', async () => {
    const q = new SequencerQueue();
    const taking = q.take();
    await q.put(intentFrom('connA', 'late'));
    expect((await taking).input.name).toBe('late');
  });

  it('accepts one oversized intent on an empty queue (no permanent block)', async () => {
    SEQUENCER_CONFIG.queueMaxBytes = 10;
    const q = new SequencerQueue();
    await q.put(intentFrom('connA', 'far-larger-than-ten-bytes'));
    expect(q.size()).toBe(1);
    SEQUENCER_CONFIG.queueMaxBytes = 1024 * 1024;
  });

  it('takeBatch drains everything queued round-robin, up to the size cap', async () => {
    const q = new SequencerQueue();
    await q.put(intentFrom('connA', 'a1'));
    await q.put(intentFrom('connA', 'a2'));
    await q.put(intentFrom('connB', 'b1'));
    const batch = await q.takeBatch(10, 1024 * 1024, 0);
    expect(batch.map((i) => i.input.name)).toEqual(['a1', 'b1', 'a2']);
    expect(q.size()).toBe(0);
    await q.put(intentFrom('connA', 'a3'));
    await q.put(intentFrom('connA', 'a4'));
    await q.put(intentFrom('connA', 'a5'));
    const capped = await q.takeBatch(2, 1024 * 1024, 0);
    expect(capped.length).toBe(2);
    expect(q.size()).toBe(1);
  });

  it('takeBatch respects the byte cap and keeps the overflow queued', async () => {
    const q = new SequencerQueue();
    const first = intentFrom('connA', 'small');
    const second = intentFrom('connA', 'this-name-is-way-larger-than-the-remaining-byte-budget');
    await q.put(first);
    await q.put(second);
    const batch = await q.takeBatch(10, first.sizeBytes + 5, 0);
    expect(batch.map((i) => i.input.name)).toEqual(['small']);
    expect(q.size()).toBe(1);
    const next = await q.takeBatch(10, 1024 * 1024, 0);
    expect(next.map((i) => i.input.name)).toEqual(['this-name-is-way-larger-than-the-remaining-byte-budget']);
  });

  it('takeBatch awaits the first intent when the queue is empty', async () => {
    const q = new SequencerQueue();
    const taking = q.takeBatch(10, 1024 * 1024, 0);
    await q.put(intentFrom('connA', 'late'));
    expect((await taking).map((i) => i.input.name)).toEqual(['late']);
  });
});

// task 0040: a source lane pops from a head index instead of Array.shift (one source held ~40k intents and shift
// moved the whole array on each pop: 20% of the busy CPU), and its storage follows the live count down
describe('sequencer source lane', () => {
  it('should keep FIFO order through shift, unshift and push', () => {
    const lane = new SourceLane<number>();
    [1, 2, 3, 4].forEach((n) => lane.push(n));
    expect(lane.shift()).toBe(1);
    expect(lane.shift()).toBe(2);
    lane.unshift(2);
    lane.push(5);
    const out: number[] = [];
    for (let n = lane.shift(); n !== undefined; n = lane.shift()) out.push(n);
    expect(out).toEqual([2, 3, 4, 5]);
    expect(lane.length).toBe(0);
  });

  it('should shrink its storage as the lane drains, not stay on the peak array', () => {
    const lane = new SourceLane<number>();
    for (let n = 0; n < 40000; n += 1) lane.push(n);
    for (let n = 0; n < 39000; n += 1) lane.shift();
    expect(lane.length).toBe(1000);
    expect(lane.capacity()).toBeLessThanOrEqual(2 * 1000 + SourceLane.COMPACT_MIN);
    expect(lane.shift()).toBe(39000);
  });

  it('should shrink while it is fed at the tail as fast as it is drained', () => {
    const lane = new SourceLane<number>();
    for (let n = 0; n < 40000; n += 1) lane.push(n);
    let next = 40000;
    for (let round = 0; round < 39000; round += 1) {
      lane.shift();
      lane.shift();
      lane.push(next);
      next += 1;
    }
    expect(lane.length).toBe(1000);
    expect(lane.capacity()).toBeLessThanOrEqual(2 * 1000 + SourceLane.COMPACT_MIN);
  });

  it('should put back in front of the head after a compaction', () => {
    const lane = new SourceLane<number>();
    for (let n = 0; n < 3 * SourceLane.COMPACT_MIN; n += 1) lane.push(n);
    let last = -1;
    for (let n = 0; n < 2 * SourceLane.COMPACT_MIN; n += 1) last = lane.shift() as number;
    lane.unshift(last);
    expect(lane.shift()).toBe(last);
    expect(lane.shift()).toBe(last + 1);
  });
});
