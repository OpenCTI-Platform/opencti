import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SequencerQueue } from '../../../src/database/sequencer/sequencer-queue';
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
