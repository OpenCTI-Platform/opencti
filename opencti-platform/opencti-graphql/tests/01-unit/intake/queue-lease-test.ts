import { describe, expect, it } from 'vitest';
import { createQueueLease, type ConsumerView, type LeaseEvent, type LeaseStore, type QueueDepth } from '../../../src/intake/workerless/queue-lease';

// The dynamic queue lease of several platforms (multi_writer): each takes its share of the queues
// holding messages, gives back the empty ones, and joins the queue of another once it has nothing left.

const memoryStore = () => {
  const leases = new Map<string, string>();
  const backlogs = new Map<string, number>();
  const ordered = new Set<string>();
  const store: LeaseStore = {
    renew: async (queue, token) => {
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
  return { store, leases };
};

const options = { ttlMs: 30000, stealBacklogMin: 100, releaseIdleTicks: 2 };
const view = (consuming: string[] = [], orderedQueues: string[] = []): ConsumerView => ({
  isOrdered: (queue) => orderedQueues.includes(queue),
  isConsuming: (queue) => consuming.includes(queue),
});

const platform = (nodeId: string, store: LeaseStore, depths: Map<string, QueueDepth>) => {
  const events: [LeaseEvent, string][] = [];
  const lease = createQueueLease(nodeId, store, async () => depths, options, (event, queue) => events.push([event, queue]));
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
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    await a.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']);
    depths.set('q1', { ready: 0, unacked: 0 });
    expect(await a.tick(['q1'], view(['q1']))).toEqual(['q1']);
    expect(await a.tick(['q1'], view(['q1']))).toEqual([]);
    expect(leases.has('q1')).toBe(true);
    // still draining: kept
    await a.tick(['q1'], view(['q1']));
    expect(leases.has('q1')).toBe(true);
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

  it('should give back every lease it holds on release', async () => {
    const { store, leases } = memoryStore();
    const a = platform('a', store, depthsOf({ q1: 500, q2: 300 }));
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    await a.lease.release();
    expect(leases.size).toBe(0);
  });
});
