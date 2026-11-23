import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  capWeight,
  drainQueue,
  fillWeighted,
  isLikelyNoop,
  NoopMemo,
  noopMemoKey,
  noopTokenOf,
  takeNoopMemoHits,
  weightedQueueDepth,
} from '../../../src/database/sequencer/sequencer-noop-memo';
import type { NoopTarget, NoopToken } from '../../../src/database/sequencer/sequencer-noop-memo';
import { SequencerQueue } from '../../../src/database/sequencer/sequencer-queue';
import { buildIntent } from '../../../src/database/sequencer/sequencer-intent';
import type { SequencerIntent } from '../../../src/database/sequencer/sequencer-intent';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// task 0040 no-op tag: an intent whose memo entry exists when it is queued is tagged a likely no-op and takes no
// slot in the batch caps (release set point, cycle drain), so a batch carries more of the writes around it. The tag
// is a hint: the memo check at batch start stays the only one that settles an intent. Each test names the wrong
// batch it guards against.

const intentOf = (name: string, type = 'External-Reference') => buildIntent({
  kind: 'entity',
  type,
  input: { source_name: 'misp', url: `https://example.com/${name}` },
  user: { id: 'u1', origin: { applicant_id: 'conn1' } } as unknown as AuthUser,
  context: {} as unknown as AuthContext,
  opts: {},
  candidateIds: [`external-reference--${name}`],
  apply: async () => null,
});

const tagged = (intent: SequencerIntent) => Object.assign(intent, { likelyNoop: true });

const tokenOf = (seqNo: number, source: Record<string, any> = { url: 'u' }): NoopToken => noopTokenOf(seqNo, 1, source);

const memoWith = (intent: SequencerIntent, targetId: string, token: NoopToken) => {
  const memo = new NoopMemo(10);
  memo.record({ key: noopMemoKey(intent) as string, result: { internal_id: targetId }, targetId, targetIndex: 'idx', targetIds: [targetId], token });
  return memo;
};

describe('isLikelyNoop: the in-memory hint, no engine read', () => {
  it('should tag an intent of a keyed type whose memo entry exists', () => {
    const intent = intentOf('a');
    const memo = memoWith(intentOf('a'), 'ref-a', tokenOf(1));
    expect(isLikelyNoop(intent, memo, new Set(['External-Reference']))).toBe(true);
  });

  it('should not tag without an entry, nor a type no apply ended as a no-op yet (its key is never computed)', () => {
    const memo = memoWith(intentOf('a'), 'ref-a', tokenOf(1));
    expect(isLikelyNoop(intentOf('b'), memo, new Set(['External-Reference']))).toBe(false);
    expect(isLikelyNoop(intentOf('a'), memo, new Set(['Label']))).toBe(false);
  });

  it('should not move the entry in the LRU (a hint must not keep an entry the batch check would evict)', () => {
    const memo = new NoopMemo(2);
    const first = intentOf('first');
    memo.record({ key: noopMemoKey(first) as string, result: {}, targetId: 'r1', targetIndex: 'idx', targetIds: ['r1'], token: tokenOf(1) });
    memo.record({ key: noopMemoKey(intentOf('second')) as string, result: {}, targetId: 'r2', targetIndex: 'idx', targetIds: ['r2'], token: tokenOf(1) });
    expect(isLikelyNoop(first, memo, new Set(['External-Reference']))).toBe(true);
    memo.record({ key: noopMemoKey(intentOf('third')) as string, result: {}, targetId: 'r3', targetIndex: 'idx', targetIds: ['r3'], token: tokenOf(1) });
    // the oldest one goes, read or not
    expect(memo.has(noopMemoKey(first) as string)).toBe(false);
  });
});

describe('fillWeighted: tagged intents take no slot, the ceiling bounds the batch', () => {
  const pull = (items: SequencerIntent[]) => () => items.shift();

  it('should take tagged intents beyond the target (a cap counted with them cuts the writes around them)', () => {
    const source = [tagged(intentOf('t1')), tagged(intentOf('t2')), intentOf('w1'), tagged(intentOf('t3')), intentOf('w2'), intentOf('w3')];
    const batch: SequencerIntent[] = [];
    fillWeighted(batch, pull(source), 2, 100, (i) => capWeight(i, true));
    expect(batch.map((i) => i.input.url.split('/').pop())).toEqual(['t1', 't2', 'w1', 't3', 'w2']);
  });

  it('should stop at the ceiling whatever the weights (a burst of tagged misses would build one giant batch)', () => {
    const source = Array.from({ length: 50 }, (_, n) => tagged(intentOf(`t${n}`)));
    const batch: SequencerIntent[] = [];
    fillWeighted(batch, pull(source), 2, 10, (i) => capWeight(i, true));
    expect(batch.length).toBe(10);
  });

  it('should count what the batch already holds against both bounds', () => {
    const batch: SequencerIntent[] = [intentOf('w0'), tagged(intentOf('t0'))];
    fillWeighted(batch, pull([intentOf('w1'), intentOf('w2')]), 2, 100, (i) => capWeight(i, true));
    expect(batch.length).toBe(3);
    const full: SequencerIntent[] = [tagged(intentOf('t1')), tagged(intentOf('t2')), tagged(intentOf('t3'))];
    fillWeighted(full, pull([intentOf('w1')]), 2, 3, (i) => capWeight(i, true));
    expect(full.length).toBe(3);
  });

  it('should be the plain count cap with the tag caps off (the default behaviour is unchanged)', () => {
    const source = [tagged(intentOf('t1')), intentOf('w1'), tagged(intentOf('t2')), intentOf('w2')];
    const batch: SequencerIntent[] = [];
    fillWeighted(batch, pull(source), 2, Infinity, (i) => capWeight(i, false));
    expect(batch.length).toBe(2);
  });

  it('should report each intent taken (queue wait recorded on first entry)', () => {
    const taken: string[] = [];
    fillWeighted([], pull([intentOf('w1'), intentOf('w2')]), 5, 100, (i) => capWeight(i, true), (i) => taken.push(i.id));
    expect(taken.length).toBe(2);
  });
});

describe('takeNoopMemoHits on a tagged intent: the tag settles nothing', () => {
  it('should apply a tagged intent whose target changed since its no-op (a hint is not a hit)', async () => {
    const intent = tagged(intentOf('a'));
    const memo = memoWith(intentOf('a'), 'ref-a', tokenOf(1, { url: 'old' }));
    const versionsOf = async (targets: NoopTarget[]) => new Map(targets.map((t) => [t.id, tokenOf(2, { url: 'new' })]));
    const { hits, rest } = await takeNoopMemoHits([intent], memo, versionsOf, new WeakMap(), new Set(['External-Reference']));
    expect(hits.length).toBe(0);
    expect(rest).toEqual([intent]);
  });
});

describe('sequencer queue untagged size: the release set point counts the writes only', () => {
  const savedIntents = SEQUENCER_CONFIG.queueMaxIntents;
  beforeAll(() => {
    SEQUENCER_CONFIG.queueMaxIntents = 100;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.queueMaxIntents = savedIntents;
  });

  it('should count untagged intents through put, pop and the byte cap put-back', async () => {
    const queue = new SequencerQueue();
    await queue.put(tagged(intentOf('t1')));
    await queue.put(intentOf('w1'));
    await queue.put(tagged(intentOf('t2')));
    expect(queue.size()).toBe(3);
    expect(queue.untaggedSize()).toBe(1);
    queue.tryPop();
    expect(queue.untaggedSize()).toBe(1);
    queue.tryPop();
    expect(queue.untaggedSize()).toBe(0);
    await queue.put(intentOf('w2'));
    await queue.put(intentOf('w3'));
    // the second one is put back over the byte cap
    const batch = await queue.takeBatch(10, 1, 0);
    expect(batch.length).toBe(1);
    expect(queue.untaggedSize()).toBe(2);
  });
});

describe('sequencer queue weighted size: tagged intents weigh in the release set point', () => {
  const savedIntents = SEQUENCER_CONFIG.queueMaxIntents;
  beforeAll(() => {
    SEQUENCER_CONFIG.queueMaxIntents = 100;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.queueMaxIntents = savedIntents;
  });

  // with tagged intents at weight 0 the release never saw them and the queue sat at queue_max_intents (40,000)
  it('should count each tagged intent at the given weight and each untagged one at 1', async () => {
    const queue = new SequencerQueue();
    for (let n = 0; n < 40; n += 1) await queue.put(tagged(intentOf(`t${n}`)));
    await queue.put(intentOf('w1'));
    expect(queue.weightedSize(1 / 20)).toBeCloseTo(3);
    expect(queue.weightedSize(1)).toBe(41);
    queue.tryPop();
    expect(queue.weightedSize(1 / 20)).toBeCloseTo(2.95);
  });
});

describe('sequencer cycle drain under the tag caps (sequencer-loop drainQueue, weightedQueueDepth)', () => {
  const sized = (intent: SequencerIntent, sizeBytes: number) => Object.assign(intent, { sizeBytes });
  const queueOf = (intents: SequencerIntent[]) => {
    const items = [...intents];
    return () => items.shift();
  };
  const tagWeight = (on: boolean) => (intent: SequencerIntent) => capWeight(intent, on);

  it('should drain as before with the caps off: weight 1 each, up to max(max batch, batch + queue share)', () => {
    const batch = [intentOf('lane1'), intentOf('lane2'), intentOf('lane3')];
    const queued = Array.from({ length: 10 }, (_, n) => tagged(intentOf(`q${n}`)));
    drainQueue(batch, queueOf(queued), { maxBatchSize: 4, queueShare: 2, ceiling: Infinity, maxBytes: Infinity, weightOf: tagWeight(false) });
    expect(batch.length).toBe(5);
  });

  it('should give the queue its share even when the lanes and the parked set already reach the ceiling (B10)', () => {
    // without the share the queued producers the parked intents wait for would never be reached
    const batch = Array.from({ length: 6 }, (_, n) => intentOf(`lane${n}`));
    const queued = Array.from({ length: 10 }, (_, n) => intentOf(`q${n}`));
    drainQueue(batch, queueOf(queued), { maxBatchSize: 2, queueShare: 2, ceiling: 4, maxBytes: Infinity, weightOf: tagWeight(true) });
    expect(batch.length).toBe(8);
  });

  it('should stop at the byte bound past the queue share under the caps (stale tags cannot make a giant batch)', () => {
    const batch: SequencerIntent[] = [];
    const queued = Array.from({ length: 10 }, (_, n) => sized(tagged(intentOf(`q${n}`)), 100));
    drainQueue(batch, queueOf(queued), { maxBatchSize: 2, queueShare: 2, ceiling: 10, maxBytes: 300, weightOf: tagWeight(true) });
    expect(batch.length).toBe(3);
  });

  it('should report the weighted depth to the release set point only under the caps', () => {
    const queue = { size: () => 41, weightedSize: (w: number) => 1 + 40 * w };
    expect(weightedQueueDepth(queue, true, 20)).toBeCloseTo(3);
    expect(weightedQueueDepth(queue, false, 20)).toBe(41);
  });
});
