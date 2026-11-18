import { describe, expect, it } from 'vitest';
import { createQueueLease, type ConsumerView, type LeaseEvent, type LeaseStore, type QueueDepth } from '../../../src/intake/workerless/queue-lease';

// The dynamic queue lease of several platforms (multi_writer): each takes its share of the queues
// holding messages, gives back the empty ones, and joins the queue of another once it has nothing left.

const memoryStore = () => {
  const leases = new Map<string, string>();
  const backlogs = new Map<string, number>();
  const ordered = new Set<string>();
  const renewed: string[] = [];
  const store: LeaseStore = {
    renew: async (queue, token) => {
      renewed.push(queue);
      const holder = leases.get(queue);
      if (holder && holder !== token) return false;
      leases.set(queue, token);
      return true;
    },
    acquire: async (queue, token) => {
      if (leases.has(queue)) return false;
      leases.set(queue, token);
      return true;
    },
    release: async (queue, token) => {
      if (leases.get(queue) !== token) return false;
      leases.delete(queue);
      return true;
    },
    holders: async (queues) => new Map(queues.map((queue) => [queue, leases.get(queue) ?? null])),
    publishBacklog: async (token, backlog) => {
      backlogs.set(token, backlog);
    },
    liveBacklogs: async () => new Map(backlogs),
    markOrdered: async (queues) => queues.forEach((queue) => ordered.add(queue)),
    ordered: async (queues) => new Set(queues.filter((queue) => ordered.has(queue))),
  };
  return { store, leases, renewed };
};

const options = { ttlMs: 30000, stealBacklogMin: 100, releaseIdleTicks: 2 };
const view = (consuming: string[] = [], orderedQueues: string[] = [], inFlight: Record<string, number> = {}): ConsumerView => ({
  isOrdered: (queue) => orderedQueues.includes(queue),
  isConsuming: (queue) => consuming.includes(queue),
  inFlight: (queue) => inFlight[queue] ?? 0,
});

const platform = (nodeId: string, store: LeaseStore, depths: Map<string, QueueDepth>, now?: () => number) => {
  const events: [LeaseEvent, string][] = [];
  const lease = createQueueLease(nodeId, store, async () => depths, { ...options, now }, (event, queue) => events.push([event, queue]));
  const tick = async (candidates: string[], consumer: ConsumerView = view()) => {
    await lease.renew();
    return lease.assign(candidates, consumer);
  };
  return { lease, events, tick };
};

const depthsOf = (ready: Record<string, number>) => new Map(Object.entries(ready).map(([queue, value]) => [queue, { ready: value, unacked: 0 }]));
const queues = ['q1', 'q2', 'q3', 'q4'];

describe('dynamic queue lease', () => {
  it('should take nothing on its first tick, then every queue holding messages when alone', async () => {
    const { store } = memoryStore();
    const a = platform('a', store, depthsOf({ q1: 500, q2: 300, q3: 0, q4: 50 }));
    expect(await a.tick(queues)).toEqual([]);
    expect(await a.tick(queues)).toEqual(['q1', 'q2', 'q4']);
    expect(a.events).toEqual([['taken', 'q1'], ['taken', 'q2'], ['taken', 'q4']]);
  });

  it('should split the queues between two platforms, each up to its share, the largest first', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 300, q3: 200, q4: 50 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(queues);
    await b.tick(queues);
    // share 525: a takes q1 (500) then q2 (800); b takes what is left
    expect(await a.tick(queues)).toEqual(['q1', 'q2']);
    expect(await b.tick(queues)).toEqual(['q3', 'q4']);
    expect(new Set(leases.values()).size).toBe(2);
  });

  it('should give back a queue empty for two ticks once its consumer is stopped, renewing it until then', async () => {
    const { store, leases, renewed } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    await a.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    depths.set('q1', { ready: 0, unacked: 0 });
    expect(await a.tick(['q1'], view(['q1']))).toEqual(['q1']);
    expect(await a.tick(['q1'], view(['q1']))).toEqual([]);
    expect(leases.has('q1')).toBe(true);
    // still draining: kept, and renewed so that it does not expire under its messages in flight
    renewed.length = 0;
    await a.tick(['q1'], view(['q1']));
    expect(leases.has('q1')).toBe(true);
    expect(renewed).toContain('q1');
    await a.tick(['q1'], view([]));
    expect(leases.has('q1')).toBe(false);
    expect(a.events.map(([event]) => event)).toEqual(['taken', 'released']);
  });

  it('should keep a queue with messages unacknowledged only (in flight)', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    await a.tick(['q1']);
    await a.tick(['q1']);
    depths.set('q1', { ready: 0, unacked: 25 });
    expect(await a.tick(['q1'])).toEqual(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
  });

  it('should stop consuming a queue whose lease another platform holds', async () => {
    const { store, leases } = memoryStore();
    // under the threshold of a steal
    const a = platform('a', store, depthsOf({ q1: 50 }));
    await a.tick(['q1']);
    await a.tick(['q1']);
    leases.set('q1', 'b:other');
    expect(await a.tick(['q1'])).toEqual([]);
    expect(a.events).toContainEqual(['lost', 'q1']);
  });

  it('should join the largest queue of another platform once it has no message ready, until it is empty', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 20 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    expect(await a.tick(['q1', 'q2'])).toEqual(['q1']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2']);
    depths.set('q2', { ready: 0, unacked: 0 });
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2', 'q1']);
    // under the threshold but not empty: kept
    depths.set('q1', { ready: 50, unacked: 25 });
    expect(await b.tick(['q1', 'q2'], view(['q2']))).toEqual(['q1']);
    depths.set('q1', { ready: 0, unacked: 25 });
    expect(await b.tick(['q1', 'q2'], view(['q2']))).toEqual([]);
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
  });

  it('should not join another queue while its own queues have messages in flight here', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 20 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2']);
    // q2 has nothing ready, but 20 messages delivered to b (a prefetch of hundreds takes them all): b is not idle
    depths.set('q2', { ready: 0, unacked: 20 });
    expect(await b.tick(['q1', 'q2'], view(['q2'], [], { q2: 20 }))).toEqual(['q2']);
    expect(await b.tick(['q1', 'q2'], view(['q2'], [], { q2: 0 }))).toEqual(['q2', 'q1']);
  });

  it('should keep a stolen queue while its messages are in flight here, nothing left ready', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 0 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1']);
    await b.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    expect(await b.tick(['q1'])).toEqual(['q1']); // stolen
    // both prefetches took every ready message: b keeps its share until it is answered
    depths.set('q1', { ready: 0, unacked: 600 });
    expect(await b.tick(['q1'], view(['q1'], [], { q1: 300 }))).toEqual(['q1']);
    expect(await b.tick(['q1'], view(['q1'], [], { q1: 1 }))).toEqual(['q1']);
    expect(await b.tick(['q1'], view(['q1'], [], { q1: 0 }))).toEqual([]);
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
  });

  it('should keep a stolen queue while its own queues only have messages in flight, until they have some ready', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 20 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2']);
    depths.set('q2', { ready: 0, unacked: 0 });
    expect(await b.tick(['q1', 'q2'], view(['q2']))).toEqual(['q2', 'q1']); // idle: stolen
    // a trickle on its own queue, delivered here at once: the steal goes on (no stop and start at each tick)
    depths.set('q2', { ready: 0, unacked: 1 });
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q2: 1, q1: 50 }))).toEqual(['q2', 'q1']);
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q2: 1, q1: 50 }))).toEqual(['q2', 'q1']);
    // messages ready on its own queue again: back to it
    depths.set('q2', { ready: 5, unacked: 1 });
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q2: 1, q1: 50 }))).toEqual(['q2']);
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
  });

  it('should not start another steal once its stolen queue is done while its own queues have messages in flight', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 20, q3: 0 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2', 'q3']);
    await b.tick(['q1', 'q2', 'q3']);
    await a.tick(['q1', 'q2', 'q3']);
    expect(await b.tick(['q1', 'q2', 'q3'])).toEqual(['q2']);
    depths.set('q2', { ready: 0, unacked: 0 });
    expect(await b.tick(['q1', 'q2', 'q3'], view(['q2']))).toEqual(['q2', 'q1']);
    // q1 done, a has another queue full, b has one message of its own in flight: no new steal
    depths.set('q1', { ready: 0, unacked: 0 });
    depths.set('q3', { ready: 500, unacked: 0 });
    expect(await a.tick(['q1', 'q2', 'q3'])).toContain('q3'); // held by a: b could only steal it
    depths.set('q2', { ready: 0, unacked: 1 });
    expect(await b.tick(['q1', 'q2', 'q3'], view(['q2', 'q1'], [], { q2: 1 }))).toEqual(['q2']);
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
  });

  it('should not join a queue under the threshold', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 80 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1']);
    await b.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    expect(await b.tick(['q1'])).toEqual([]);
  });

  it('should not join a queue that carried events, marked by its holder', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1']);
    await b.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    // an event consumed: marked on the next tick
    expect(await a.tick(['q1'], view(['q1'], ['q1']))).toEqual(['q1']);
    expect(await b.tick(['q1'])).toEqual([]);
  });

  it('should give back every lease it holds on release, those still draining included', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 300 });
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    // q2 no longer listed: given back once drained, its consumer still running
    expect(await a.tick(['q1'], view(['q1', 'q2']))).toEqual(['q1']);
    expect(leases.has('q2')).toBe(true);
    await a.lease.release();
    expect(leases.size).toBe(0);
  });

  it('should let another platform take a queue given back after its drain', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1']);
    await b.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    const tokenOfA = leases.get('q1');
    // q1 empty for two ticks, then drained: given back
    depths.set('q1', { ready: 0, unacked: 0 });
    await a.tick(['q1'], view(['q1']));
    await a.tick(['q1'], view(['q1']));
    await a.tick(['q1'], view([]));
    expect(leases.has('q1')).toBe(false);
    depths.set('q1', { ready: 300, unacked: 0 });
    expect(await b.tick(['q1'])).toEqual(['q1']);
    // taken by b, not a steal of a lease a still holds
    expect(leases.get('q1')).toBeDefined();
    expect(leases.get('q1')).not.toBe(tokenOfA);
  });

  it('should give back a held queue no longer listed (connector removed)', async () => {
    const { store, leases } = memoryStore();
    const a = platform('a', store, depthsOf({ q1: 500, q2: 300 }));
    await a.tick(['q1', 'q2']);
    expect(await a.tick(['q1', 'q2'])).toEqual(['q1', 'q2']);
    // given back on the tick after: its consumer is stopped by then
    expect(await a.tick(['q1'], view(['q1', 'q2']))).toEqual(['q1']);
    expect(leases.has('q2')).toBe(true);
    await a.tick(['q1'], view(['q1']));
    expect(leases.has('q2')).toBe(false);
  });

  it('should take beyond its share when it is the least loaded platform, so that no queue is left unconsumed', async () => {
    const { store } = memoryStore();
    // another live platform loaded with queues this one does not list
    await store.publishBacklog('c:other', 5000);
    const b = platform('b', store, depthsOf({ q1: 300, q2: 300 }));
    await b.tick(['q1', 'q2']);
    // share 300 (600 over two live platforms): b reaches it with q1 but is the least loaded, so it takes q2 too
    expect(await b.tick(['q1', 'q2'])).toEqual(['q1', 'q2']);
  });

  it('should not join a queue its own consumer saw carrying events', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1']);
    await b.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    expect(await b.tick(['q1'], view([], ['q1']))).toEqual([]);
  });

  it('should mark a queue ordered at once, before any tick', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1']);
    await b.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    await a.lease.markOrdered('q1');
    expect(await b.tick(['q1'])).toEqual([]);
  });

  it('should take a free queue marked ordered only once seen free for a lease TTL', async () => {
    const { store, leases } = memoryStore();
    let clock = 0;
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths, () => clock);
    await a.tick(['q1']);
    // given back by a previous holder that consumed events from it
    await store.markOrdered(['q1']);
    expect(await a.tick(['q1'])).toEqual([]);
    clock += options.ttlMs - 1;
    expect(await a.tick(['q1'])).toEqual([]);
    clock += 1;
    expect(await a.tick(['q1'])).toEqual(['q1']);
    expect(leases.get('q1')).toBeDefined();
  });
});
