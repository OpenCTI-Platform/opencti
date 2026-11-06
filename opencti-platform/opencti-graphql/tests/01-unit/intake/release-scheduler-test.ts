import { describe, expect, it } from 'vitest';
import { createReleaseScheduler, type ReleaseHooks, type ScheduledNode } from '../../../src/intake/workerless/release-scheduler';

// The release scheduler: an operation starts once what it depends on is queued (a sequenced
// creation) or settled (a direct operation, or a producer whose answer it needs), and only while
// the sequencer's ready depth is below the set point.

const flush = () => new Promise((resolve) => {
  setImmediate(resolve);
});

// A fake sequencer: the queue depth is set by hand, each started operation is driven by hand
const harness = (initialSetPoint = 100, quantum?: number) => {
  let depth = 0;
  let setPoint = initialSetPoint;
  const started: string[] = [];
  const controls = new Map<string, { hooks: ReleaseHooks; settle: (result: string) => void }>();
  const scheduler = createReleaseScheduler({ queueDepth: () => depth, setPoint: () => setPoint, quantum });
  const runOf = (name: string) => (index: number, hooks: ReleaseHooks) => new Promise<string>((resolve) => {
    const key = `${name}:${index}`;
    started.push(key);
    controls.set(key, { hooks, settle: resolve });
  });
  const queue = async (key: string) => {
    controls.get(key)?.hooks.queued();
    await flush();
  };
  const settle = async (key: string, result = 'ok') => {
    controls.get(key)?.settle(result);
    await flush();
  };
  return {
    scheduler,
    started,
    runOf,
    queue,
    settle,
    setDepth: (value: number) => {
      depth = value;
    },
    setSetPoint: (value: number) => {
      setPoint = value;
    },
  };
};
const node = (kind: 'sequenced' | 'direct', deps: number[] = [], extra: Partial<ScheduledNode> = {}): ScheduledNode => ({
  kind, deps, creates: [], external: [], ...extra,
});

describe('Release scheduler', () => {
  it('should start a sequenced creation once its producer is queued, a direct operation once it is written', async () => {
    const h = harness();
    const done = h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced'), node('sequenced', [0]), node('direct', [0])], run: h.runOf('m') });
    await flush();
    expect(h.started).toEqual(['m:0']);
    await h.queue('m:0');
    // the creation follows its producer into the queue (same batch or a later one), the edit waits
    expect(h.started).toEqual(['m:0', 'm:1']);
    await h.settle('m:0');
    expect(h.started).toEqual(['m:0', 'm:1', 'm:2']);
    await h.settle('m:1');
    await h.settle('m:2', 'edited');
    expect(await done).toEqual(['ok', 'ok', 'edited']);
  });

  it('should wait for a producer whose answer it needs to be written, whatever its kind', async () => {
    const h = harness();
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced', [], { answerNeeded: true }), node('sequenced', [0])], run: h.runOf('m') });
    await flush();
    await h.queue('m:0');
    expect(h.started).toEqual(['m:0']);
    await h.settle('m:0');
    expect(h.started).toEqual(['m:0', 'm:1']);
  });

  it('should release only while the ready depth is below the set point', async () => {
    const h = harness(3);
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced'), node('sequenced'), node('sequenced'), node('sequenced'), node('sequenced')], run: h.runOf('m') });
    await flush();
    // three released, none queued yet: R = 3
    expect(h.started).toEqual(['m:0', 'm:1', 'm:2']);
    // queued: still in R through the sequencer queue
    h.setDepth(3);
    await h.queue('m:0');
    await h.queue('m:1');
    await h.queue('m:2');
    expect(h.started).toHaveLength(3);
    // the sequencer takes its batch: room for two more
    h.setDepth(1);
    h.scheduler.notify();
    await flush();
    expect(h.started).toEqual(['m:0', 'm:1', 'm:2', 'm:3', 'm:4']);
    expect(h.scheduler.stats()).toMatchObject({ waiting: 0, ready: 0, pre_loop: 2 });
  });

  it('should serve the sources in turn', async () => {
    const h = harness(0);
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced'), node('sequenced'), node('sequenced')], run: h.runOf('a') });
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced')], run: h.runOf('a2') });
    void h.scheduler.admit({ source: 'b', lane: 'w', nodes: [node('sequenced'), node('sequenced')], run: h.runOf('b') });
    await flush();
    // no room: nothing starts
    expect(h.started).toEqual([]);
    h.setSetPoint(5);
    h.scheduler.notify();
    await flush();
    // one operation of each source in turn, each source in its own order
    expect(h.started).toEqual(['a:0', 'b:0', 'a:1', 'b:1', 'a:2']);
  });

  it('should release up to quantum operations of a source per turn', async () => {
    const h = harness(0, 2);
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced'), node('sequenced'), node('sequenced')], run: h.runOf('a') });
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced')], run: h.runOf('a2') });
    void h.scheduler.admit({ source: 'b', lane: 'w', nodes: [node('sequenced'), node('sequenced'), node('sequenced')], run: h.runOf('b') });
    void h.scheduler.admit({ source: 'c', lane: 'w', nodes: [node('sequenced')], run: h.runOf('c') });
    await flush();
    h.setSetPoint(6);
    h.scheduler.notify();
    await flush();
    // two of a, two of b, the only one of c, then a's turn again across its messages
    expect(h.started).toEqual(['a:0', 'a:1', 'b:0', 'b:1', 'c:0', 'a:2']);
    h.setSetPoint(8);
    h.scheduler.notify();
    await flush();
    // a's turn goes on (one served), then b's last
    expect(h.started.slice(6)).toEqual(['a2:0', 'b:2']);
  });

  it('should make an operation wait for an id an earlier message creates, until that write is queued', async () => {
    const h = harness();
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced', [], { creates: ['identity--1'] })], run: h.runOf('first') });
    void h.scheduler.admit({
      source: 'a',
      lane: 'w',
      nodes: [node('sequenced', [], { external: ['identity--1'] }), node('direct', [], { external: ['identity--1'] }), node('sequenced', [], { external: ['identity--2'] })],
      run: h.runOf('second'),
    });
    await flush();
    // the unrelated operation starts, the two referencing the author wait
    expect(h.started).toEqual(['first:0', 'second:2']);
    await h.queue('first:0');
    expect(h.started).toEqual(['first:0', 'second:2', 'second:0']);
    await h.settle('first:0');
    expect(h.started).toEqual(['first:0', 'second:2', 'second:0', 'second:1']);
    // settled: no longer in flight, a later message does not wait for it
    void h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('direct', [], { external: ['identity--1'] })], run: h.runOf('third') });
    await flush();
    expect(h.started).toContain('third:0');
  });

  it('should answer an empty message at once and a message once all its operations settled', async () => {
    const h = harness();
    expect(await h.scheduler.admit({ source: 'a', lane: 'w', nodes: [], run: h.runOf('empty') })).toEqual([]);
    let answered = false;
    const done = h.scheduler.admit({ source: 'a', lane: 'w', nodes: [node('sequenced'), node('sequenced')], run: h.runOf('m') }).then((results) => {
      answered = true;
      return results;
    });
    await flush();
    await h.settle('m:1', 'second');
    expect(answered).toBe(false);
    await h.settle('m:0', 'first');
    expect(await done).toEqual(['first', 'second']);
  });
  it('should make an operation wait for the write of an id another writer creates, queued is not enough', async () => {
    const h = harness();
    void h.scheduler.admit({ source: 'a', lane: 'connector-1', nodes: [node('sequenced', [], { creates: ['identity--1'] })], run: h.runOf('first') });
    void h.scheduler.admit({ source: 'b', lane: 'connector-2', nodes: [node('sequenced', [], { external: ['identity--1'] })], run: h.runOf('second') });
    await flush();
    await h.queue('first:0');
    // another source of the sequencer queue: its batch may come after the consumer's
    expect(h.started).toEqual(['first:0']);
    await h.settle('first:0');
    expect(h.started).toEqual(['first:0', 'second:0']);
  });
});
