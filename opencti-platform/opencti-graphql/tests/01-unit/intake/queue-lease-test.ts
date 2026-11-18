import { describe, expect, it } from 'vitest';
import { createQueueLease, queueLoads, type ConsumerView, type LeaseEvent, type LeaseStore, type QueueDepth } from '../../../src/intake/workerless/queue-lease';

// The dynamic queue lease of several platforms (multi_writer): each takes its share of the queues
// holding messages, gives back the empty ones, and joins the queue of another once it has nothing left.

// As Redis: a lease expires after its TTL (free again, renewed only by its holder or taken back once free), a platform
// is live while it published within the TTL; the clock is the test's
const memoryStore = (clock: () => number = () => 0) => {
  const held = new Map<string, { token: string; until: number }>();
  const published = new Map<string, { load: number; messages: number; at: number }>();
  // platforms of the previous version (message counts, another hash): live, load unknown
  const legacy = new Map<string, number>();
  const ordered = new Set<string>();
  const renewed: string[] = [];
  const holder = (queue: string) => {
    const lease = held.get(queue);
    return lease && lease.until > clock() ? lease.token : undefined;
  };
  // the holders still valid, by queue (the tests read and set them)
  const leases = {
    get: (queue: string) => holder(queue),
    has: (queue: string) => holder(queue) !== undefined,
    set: (queue: string, token: string) => held.set(queue, { token, until: clock() + 30000 }),
    values: () => [...held.keys()].map(holder).filter((token): token is string => !!token),
    get size() {
      return leases.values().length;
    },
  };
  const store: LeaseStore = {
    renew: async (queue, token, ttlMs) => {
      renewed.push(queue);
      const current = holder(queue);
      if (current && current !== token) return false;
      held.set(queue, { token, until: clock() + ttlMs });
      return true;
    },
    acquire: async (queue, token, ttlMs) => {
      if (holder(queue)) return false;
      held.set(queue, { token, until: clock() + ttlMs });
      return true;
    },
    release: async (queue, token) => {
      if (holder(queue) !== token) return false;
      held.delete(queue);
      return true;
    },
    holders: async (queues) => new Map(queues.map((queue) => [queue, holder(queue) ?? null])),
    publishBacklog: async (token, load, messages) => {
      published.set(token, { load, messages, at: clock() });
    },
    liveBacklogs: async (ttlMs) => new Map<string, number | null>([
      ...[...legacy].filter(([, at]) => clock() - at <= ttlMs).map(([token]): [string, null] => [token, null]),
      ...[...published].filter(([, { at }]) => clock() - at <= ttlMs).map(([token, { load }]): [string, number] => [token, load]),
    ]),
    unpublish: async (token) => {
      published.delete(token);
    },
    markOrdered: async (queues) => queues.forEach((queue) => ordered.add(queue)),
    ordered: async (queues) => new Set(queues.filter((queue) => ordered.has(queue))),
  };
  return { store, leases, renewed, published, legacy };
};

const options = { ttlMs: 30000, stealBacklogMin: 100, releaseIdleTicks: 2, shed: true, stealUnderloaded: true };
// stopping: stopped and draining (as push-consumer: channel still open, not consumed again before it is closed)
const view = (consuming: string[] = [], orderedQueues: string[] = [], inFlight: Record<string, number> = {}, stopping: string[] = []): ConsumerView => ({
  isOrdered: (queue) => orderedQueues.includes(queue),
  isConsuming: (queue) => consuming.includes(queue) || stopping.includes(queue),
  isStopping: (queue) => stopping.includes(queue),
  inFlight: (queue) => inFlight[queue] ?? 0,
});

type Read = () => Promise<Map<string, QueueDepth>>;
const platform = (nodeId: string, store: LeaseStore, depths: Map<string, QueueDepth>, now?: () => number, overrides: Partial<typeof options> = {}, read?: Read) => {
  const events: [LeaseEvent, string][] = [];
  const details: [LeaseEvent, string, Record<string, number> | undefined][] = [];
  const lease = createQueueLease(nodeId, store, read ?? (async () => depths), { ...options, ...overrides, now }, (event, queue, detail) => {
    events.push([event, queue]);
    details.push([event, queue, detail]);
  });
  const tick = async (candidates: string[], consumer: ConsumerView = view()) => {
    await lease.renew();
    return lease.assign(candidates, consumer);
  };
  return { lease, events, details, tick };
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

  it('should split the queues between two platforms, the largest first, each taking the queues that fit its share', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 300, q3: 200, q4: 50 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(queues);
    await b.tick(queues);
    // share 525: a takes q1 (500, nothing held), not q2 (500 + 300 / 2 over it) nor q3 (600), q4 (525) fits
    expect(await a.tick(queues)).toEqual(['q1', 'q4']);
    expect(await b.tick(queues)).toEqual(['q2', 'q3']);
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
    const b = platform('b', store, depths, undefined, { stealUnderloaded: false }); // the idle rule alone
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
    const b = platform('b', store, depths, undefined, { stealUnderloaded: false }); // the idle rule alone
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
    const b = platform('b', store, depths, undefined, { stealUnderloaded: false }); // the idle rule alone
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
    const b = platform('b', store, depths, undefined, { stealUnderloaded: false }); // the idle rule alone
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
    await store.publishBacklog('c:other', 5000, 0);
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

// Several platforms ticking in turn on one store, 10 s per round; a platform's consumer runs the queues its last tick
// returned (a queue given back is stopped by its next tick)
const cluster = (depths: Map<string, QueueDepth>, queues: string[], overrides: Partial<typeof options> = {}) => {
  let clock = 0;
  const { store, leases, published } = memoryStore(() => clock);
  // platforms whose management API reads fail
  const blind = new Set<string>();
  // Each node's consumer, as push-consumer: queue -> stopping. A queue no longer consumed stops and is closed at once,
  // unless a message of it hangs here (stuck): then it stays stopping, and is not consumed again even if listed again
  type Node = { p: ReturnType<typeof platform>; listed: string[]; consumed: Map<string, boolean>; stuck: Set<string> };
  const nodes = new Map<string, Node>();
  const read = (id: string) => async () => {
    if (blind.has(id)) throw new Error('management API unreachable');
    return depths;
  };
  const add = (id: string, stuck: string[] = []) => nodes.set(id, {
    p: platform(id, store, depths, () => clock, overrides, read(id)),
    listed: [],
    consumed: new Map(stuck.map((queue) => [queue, true])),
    stuck: new Set(stuck),
  });
  const consumerOf = ({ consumed, stuck }: Node) => view(
    [...consumed.keys()],
    [],
    Object.fromEntries([...stuck].map((queue) => [queue, 1])),
    [...consumed].filter(([, stopping]) => stopping).map(([queue]) => queue),
  );
  const round = async (alive: string[] = [...nodes.keys()]) => {
    for (const id of alive) {
      const node = nodes.get(id) as Node;
      const listed = await node.p.tick(queues, consumerOf(node));
      node.listed = listed;
      listed.filter((queue) => !node.consumed.has(queue)).forEach((queue) => node.consumed.set(queue, false));
      [...node.consumed].filter(([queue, stopping]) => !stopping && !listed.includes(queue)).forEach(([queue]) => {
        if (node.stuck.has(queue)) node.consumed.set(queue, true);
        else node.consumed.delete(queue);
      });
    }
    clock += 10000;
  };
  // consumed by a platform whose consumer on it is not stopping
  const consumedBySomeone = (queue: string) => [...nodes.values()].some(({ consumed }) => consumed.get(queue) === false);
  const { load } = queueLoads(depths);
  // the load each platform holds, from the leases
  const heldBy = (id: string) => queues.filter((queue) => leases.get(queue)?.startsWith(`${id}:`));
  const loads = () => new Map([...nodes.keys()].map((id) => [id, heldBy(id).reduce((sum, queue) => sum + load(queue), 0)]));
  const count = (event: LeaseEvent) => [...nodes.values()].reduce((sum, { p }) => sum + p.events.filter(([e]) => e === event).length, 0);
  return { store, leases, published, blind, nodes, add, round, loads, count, heldBy, consumedBySomeone };
};
const ladder = (sizes: number[]) => depthsOf(Object.fromEntries(sizes.map((size, i) => [`q${i + 1}`, size])));
const bytesOf = (spec: Record<string, [number, number]>) => new Map(Object.entries(spec)
  .map(([queue, [messages, bytes]]) => [queue, { ready: messages, unacked: 0, bytesReady: bytes, bytesUnacked: 0 }]));

describe('queue lease load (task 0040 L3)', () => {
  it('should weigh a queue by the bytes of its messages ready and unacked', () => {
    const { load, readyLoad } = queueLoads(new Map([['q1', { ready: 10, unacked: 5, bytesReady: 1000, bytesUnacked: 500 }]]));
    expect(load('q1')).toBe(1500);
    expect(readyLoad('q1')).toBe(1000);
    expect(load('unknown')).toBe(0);
  });

  it('should count the messages of a queue not sampled yet at the mean size of the known ones', () => {
    const { load, readyLoad } = queueLoads(new Map([
      ['q1', { ready: 10, unacked: 0, bytesReady: 1000, bytesUnacked: 0 }],
      ['q2', { ready: 4, unacked: 1, bytesReady: 0, bytesUnacked: 0 }],
    ]));
    expect(load('q2')).toBe(500); // 5 messages x 100 bytes
    expect(readyLoad('q2')).toBe(400);
  });

  it('should fall back to message counts when no byte is known', () => {
    const { load } = queueLoads(depthsOf({ q1: 30 }));
    expect(load('q1')).toBe(30);
  });

  it('should take the largest queue in bytes first, not in messages', async () => {
    const { store } = memoryStore();
    const depths = bytesOf({ q1: [10, 1_000_000_000], q2: [1000, 10_000_000] });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    expect(await a.tick(['q1', 'q2'])).toEqual(['q1']); // 1 GB: its share at once
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2']);
  });
});

describe('queue lease rebalancing (task 0040 L1, L2)', () => {
  it('should spread the queues again when a platform joins, then stop moving them (2 -> 3, queues never drained)', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4', 'q5', 'q6'];
    const c = cluster(ladder([600, 500, 400, 300, 200, 100]), queues);
    c.add('a');
    c.add('b');
    for (let i = 0; i < 20; i += 1) await c.round();
    c.add('c');
    for (let i = 0; i < 30; i += 1) await c.round();
    const settled = c.count('shed');
    for (let i = 0; i < 10; i += 1) await c.round();
    expect(c.count('shed')).toBe(settled); // no more moves
    const loads = [...c.loads().values()];
    const share = 2100 / 3;
    // the shedding stop: no platform well above its share while another is well under
    expect(Math.max(...loads) <= 1.25 * share || Math.min(...loads) >= 0.75 * share).toBe(true);
    expect(Math.min(...loads)).toBeGreaterThan(0); // the newcomer got queues
    expect(settled).toBeLessThanOrEqual(2); // a queue goes to the platform it fits: no shed passed on
    expect(Math.min(...loads)).toBeGreaterThanOrEqual(0.75 * share);
    expect(queues.every((queue) => c.leases.has(queue))).toBe(true);
  });

  it('should never shed a queue larger than the gap: the dominant queue is joined, not moved', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4'];
    const c = cluster(ladder([10000, 100, 100, 100]), queues);
    c.add('a');
    c.add('b');
    for (let i = 0; i < 30; i += 1) await c.round();
    expect(c.count('shed')).toBe(0);
    expect(c.leases.get('q1')?.startsWith('a:')).toBe(true);
    // b, under half its share, joins q1 once and stays on it
    expect(c.nodes.get('b')?.p.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1']]);
    expect(c.nodes.get('b')?.listed).toContain('q1');
  });

  it('should shed one queue at a time, the next only once the first is given back', async () => {
    const { store, leases } = memoryStore();
    const depths = ladder([300, 300, 300, 300]);
    const queues = ['q1', 'q2', 'q3', 'q4'];
    const a = platform('a', store, depths);
    await a.tick(queues);
    await a.tick(queues); // alone: all
    await store.publishBacklog('b:other', 0, 0); // an empty platform appears
    const consuming = [...queues];
    for (let i = 0; i < 9; i += 1) {
      await a.tick(queues, view(consuming)); // its consumer never stops the shed queue: still draining
      await store.publishBacklog('b:other', 0, 0);
    }
    expect(a.events.filter(([event]) => event === 'shed')).toHaveLength(1);
    expect(leases.size).toBe(4); // the shed one still held while it drains
  });

  it('should not take back a queue it shed until it waited free a few ticks, nor shed a queue it took recently', async () => {
    const { store, leases } = memoryStore();
    const depths = ladder([300, 300, 300, 300]);
    const queues = ['q1', 'q2', 'q3', 'q4'];
    const a = platform('a', store, depths);
    await a.tick(queues);
    expect(await a.tick(queues)).toEqual(queues);
    // a platform appears: a is over its share; its queues were taken 1 tick ago, none shed for the cooldown
    for (let i = 0; i < 5; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      await a.tick(queues, view(queues));
    }
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
    await store.publishBacklog('b:other', 0, 0);
    const kept = await a.tick(queues, view(queues));
    expect(a.events.filter(([event]) => event === 'shed')).toHaveLength(1);
    const shed = queues.find((queue) => !kept.includes(queue)) as string;
    // b now the most loaded: a is the least loaded, only its shed refuses the queue
    await store.publishBacklog('b:other', 5000, 0);
    expect(await a.tick(queues, view(kept))).not.toContain(shed); // stopped: given back, free from now
    expect(leases.has(shed)).toBe(false);
    await store.publishBacklog('b:other', 5000, 0);
    expect(await a.tick(queues, view(kept))).not.toContain(shed);
    // nobody took it for two ticks: taken back, starving
    await store.publishBacklog('b:other', 5000, 0);
    expect(await a.tick(queues, view(kept))).toContain(shed);
  });

  it('should never shed a queue that carried events', async () => {
    const { store } = memoryStore();
    const depths = ladder([300, 300]);
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    for (let i = 0; i < 12; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      await a.tick(['q1', 'q2'], view(['q1', 'q2'], ['q1', 'q2']));
    }
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
  });

  it('should never shed a queue marked ordered by an earlier holder, its consumer here seeing no event yet', async () => {
    const { store } = memoryStore();
    const depths = ladder([300, 300]);
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    await store.markOrdered(['q1', 'q2']);
    for (let i = 0; i < 12; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      await a.tick(['q1', 'q2'], view(['q1', 'q2']));
    }
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
  });

  // a holds the queues long enough (cooldown passed) before another platform is seen, b's load published at will
  const settledHolder = async (sizes: number[], others: Record<string, number> = {}) => {
    const { store, leases } = memoryStore();
    const depths = ladder(sizes);
    const queues = sizes.map((_, i) => `q${i + 1}`);
    const mine = queues.filter((queue) => !(queue in others));
    const a = platform('a', store, depths);
    for (let i = 0; i < 8; i += 1) await a.tick(mine, view(i < 2 ? [] : mine)); // consumed from the tick after the take
    Object.keys(others).forEach((queue) => leases.set(queue, 'b:other'));
    const tick = async (bLoad: number) => {
      await store.publishBacklog('b:other', bLoad, 0);
      return a.tick(queues, view(mine));
    };
    return { a, tick, mine };
  };

  it('should shed the queue closest to half the gap, not the largest one under it', async () => {
    const { a, tick } = await settledHolder([1100, 500, 100]);
    for (let i = 0; i < 3; i += 1) await tick(300); // share 850, own 1700, gap 1400
    expect(a.events.filter(([event]) => event === 'shed')).toEqual([['shed', 'q2']]);
  });

  it('should shed only after 3 ticks in a row above the threshold', async () => {
    const { a, tick } = await settledHolder([300, 300, 300, 300]);
    await tick(0);
    await tick(0);
    await tick(1000); // b not under any more: the count restarts
    await tick(0);
    await tick(0);
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
    await tick(0);
    expect(a.events.filter(([event]) => event === 'shed')).toHaveLength(1);
  });

  it('should not shed at 1.2 x its share, nor while the least loaded is at 0.8 x its share', async () => {
    // a 1200 of a share of 1000 (q5 held by b): under 1.25 x
    const low = await settledHolder([300, 300, 300, 300, 800], { q5: 1 });
    for (let i = 0; i < 6; i += 1) await low.tick(0);
    expect(low.a.events.some(([event]) => event === 'shed')).toBe(false);
    // a 1600 of 1000, b at 800: not under 0.75 x
    const high = await settledHolder([400, 400, 400, 400, 400], { q5: 1 });
    for (let i = 0; i < 6; i += 1) await high.tick(800);
    expect(high.a.events.some(([event]) => event === 'shed')).toBe(false);
    for (let i = 0; i < 3; i += 1) await high.tick(700);
    expect(high.a.events.filter(([event]) => event === 'shed')).toHaveLength(1);
  });

  it('should not shed with the option off', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4'];
    const c = cluster(ladder([300, 300, 300, 300]), queues, { shed: false });
    c.add('a');
    for (let i = 0; i < 3; i += 1) await c.round();
    c.add('b');
    for (let i = 0; i < 20; i += 1) await c.round();
    expect(c.count('shed')).toBe(0);
  });

  it('should take as its own the queue it steals once its holder is gone, its consumer going on', async () => {
    const queues = ['q1', 'q2'];
    const c = cluster(ladder([10000, 10]), queues);
    c.add('a');
    c.add('b');
    for (let i = 0; i < 5; i += 1) await c.round();
    expect(c.nodes.get('b')?.listed).toEqual(['q2', 'q1']); // stealing q1
    // a dies: its lease expires after the TTL, b takes q1
    for (let i = 0; i < 5; i += 1) await c.round(['b']);
    expect(c.leases.get('q1')?.startsWith('b:')).toBe(true);
    expect(c.nodes.get('b')?.listed).toEqual(['q2', 'q1']); // once
    // the steal ends as its own (steal_stop, its consumer going on: the queue still listed once)
    expect(c.nodes.get('b')?.p.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
    expect(c.nodes.get('b')?.p.details).toContainEqual(['steal_stop', 'q1', { taken: 1 }]);
  });

  it('should take over the queues of a platform that died, once its leases expired (3 -> 2)', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4', 'q5', 'q6'];
    const c = cluster(ladder([300, 300, 300, 300, 300, 300]), queues);
    c.add('a');
    c.add('b');
    c.add('c');
    for (let i = 0; i < 20; i += 1) await c.round();
    expect([...c.loads().values()].every((value) => value > 0)).toBe(true);
    for (let i = 0; i < 10; i += 1) await c.round(['a', 'b']); // c killed
    expect(queues.every((queue) => c.leases.get(queue) && !c.leases.get(queue)?.startsWith('c:'))).toBe(true);
  });

  it('should rebalance once queues of one platform drained', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4'];
    const depths = ladder([300, 300, 300, 300]);
    const c = cluster(depths, queues);
    c.add('a');
    c.add('b');
    for (let i = 0; i < 10; i += 1) await c.round();
    const ofB = queues.filter((queue) => c.leases.get(queue)?.startsWith('b:'));
    ofB.forEach((queue) => depths.set(queue, { ready: 0, unacked: 0 })); // b's connectors done
    for (let i = 0; i < 20; i += 1) await c.round();
    const loads = c.loads();
    expect(loads.get('b')).toBeGreaterThan(0); // b got one of a's queues
    expect(c.count('shed')).toBeGreaterThanOrEqual(1);
  });

  it('should keep a steal started under half its share while it stays under 3/4 of it, own messages ready', async () => {
    const { store } = memoryStore();
    const depths = ladder([2000, 100]);
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    // b: 100 of a share of 1050, messages ready on q2: under half, q1 above a share
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2', 'q1']);
    depths.set('q2', { ready: 700, unacked: 0 }); // 700 of 1350: between 1/2 and 3/4, kept
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q1: 50 }))).toEqual(['q2', 'q1']);
    depths.set('q2', { ready: 1500, unacked: 0 }); // above 3/4 with messages ready: back to its own
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q1: 50 }))).toEqual(['q2']);
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
  });

  it('should not steal, under half its share, a queue smaller than a share (shedding moves it)', async () => {
    const { store } = memoryStore();
    const depths = ladder([400, 400, 50]);
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    expect(await a.tick(['q1', 'q2'])).toEqual(['q1', 'q2']); // alone
    const b = platform('b', store, depths);
    await b.tick(['q1', 'q2', 'q3']);
    await a.tick(['q1', 'q2', 'q3'], view(['q1', 'q2']));
    // b: 50 of a share of 425, messages ready on q3, under half: q1 and q2 (400 each) are not above a share
    expect(await b.tick(['q1', 'q2', 'q3'])).toEqual(['q3']);
    expect(await b.tick(['q1', 'q2', 'q3'])).toEqual(['q3']);
    expect(b.events.some(([event]) => event === 'steal_start')).toBe(false);
  });
});

describe('queue lease rebalancing, review round 1 fixes (task 0040)', () => {
  const settled = async (sizes: number[], depths = ladder(sizes)) => {
    const { store, leases, published } = memoryStore();
    const queues = sizes.map((_, i) => `q${i + 1}`);
    const a = platform('a', store, depths);
    for (let i = 0; i < 8; i += 1) await a.tick(queues, view(i < 2 ? [] : queues)); // consumed from the tick after the take
    return { store, leases, published, a, queues, depths };
  };

  it('should not steal back a queue it shed before the cooldown, then may join it like any stealer', async () => {
    const queues = ['q1', 'q2', 'q3'];
    const c = cluster(depthsOf({ q1: 1200, q2: 50, q3: 50 }), queues);
    c.add('a');
    for (let i = 0; i < 9; i += 1) await c.round();
    c.add('b');
    const a = c.nodes.get('a')?.p.events ?? [];
    let shedRound = -1;
    let stealRound = -1;
    for (let i = 0; i < 20; i += 1) {
      await c.round();
      if (shedRound < 0 && a.some(([event, queue]) => event === 'shed' && queue === 'q1')) shedRound = i;
      if (stealRound < 0 && a.some(([event, queue]) => event === 'steal_start' && queue === 'q1')) stealRound = i;
    }
    expect(shedRound).toBeGreaterThanOrEqual(0);
    expect(c.leases.get('q1')?.startsWith('b:')).toBe(true);
    // under half its share beside a queue larger than a share: it joins it, but not within the cooldown
    expect(stealRound - shedRound).toBeGreaterThanOrEqual(6);
  });

  it('should let several platforms steal the same queue larger than a share', async () => {
    const queues = ['q1', 'q2', 'q3'];
    const c = cluster(depthsOf({ q1: 10000, q2: 100, q3: 100 }), queues);
    c.add('a');
    c.add('b');
    c.add('c');
    for (let i = 0; i < 10; i += 1) await c.round();
    const consumers = [...c.nodes.values()].filter(({ listed }) => listed.includes('q1'));
    expect(consumers).toHaveLength(3); // its holder and two stealers
  });

  it('should shed only a queue with steal_backlog_min messages ready (what moves), not one whose work is in flight here', async () => {
    const depths = new Map<string, QueueDepth>(['q1', 'q2', 'q3', 'q4'].map((queue) => [queue, { ready: 0, unacked: 300 }]));
    const { store, a, queues } = await settled([300, 300, 300, 300], depths);
    const over = async (ticks: number) => {
      for (let i = 0; i < ticks; i += 1) {
        await store.publishBacklog('b:other', 0, 0);
        await a.tick(queues, view(queues));
      }
    };
    await over(8);
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
    depths.set('q2', { ready: 99, unacked: 300 }); // under the floor
    await over(4);
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
    depths.set('q2', { ready: 100, unacked: 300 });
    await over(3);
    expect(a.events.filter(([event]) => event === 'shed')).toEqual([['shed', 'q2']]);
  });

  it('should release a shed still draining after the cooldown (a stuck message), not take it back, and shed the next', async () => {
    const { store, leases, a, queues } = await settled([300, 300, 300, 300, 300, 300]);
    const shedTicks: number[] = [];
    let first = '';
    let freedAt = -1;
    for (let i = 0; i < 20; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      // its consumer never ends the drain of a shed queue (stopping)
      const shed = a.events.filter(([event]) => event === 'shed').map(([, queue]) => queue);
      await a.tick(queues, view(queues.filter((queue) => !shed.includes(queue)), [], {}, shed));
      const sheds = a.events.filter(([event]) => event === 'shed');
      if (sheds.length > shedTicks.length) shedTicks.push(i);
      first = sheds[0]?.[1] ?? '';
      if (first && freedAt < 0 && !leases.has(first)) freedAt = i;
    }
    expect(shedTicks.length).toBeGreaterThanOrEqual(2);
    expect(shedTicks[1] - shedTicks[0]).toBe(6);
    // given back for good after the cooldown: free for another platform, never taken back while its consumer drains
    expect(freedAt - shedTicks[0]).toBe(6);
    expect(a.details).toContainEqual(['released', first, { still_draining: 1 }]);
    expect(leases.has(first)).toBe(false);
    expect(a.events.filter(([event, queue]) => event === 'taken' && queue === first)).toHaveLength(1);
  });

  it('should need 3 more ticks over its share after a shed given back', async () => {
    const { store, a, queues } = await settled([300, 300, 300, 300, 300, 300]);
    let consuming = [...queues];
    const shedTicks: number[] = [];
    for (let i = 0; i < 8; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      consuming = await a.tick(queues, view(consuming)); // a queue given back is stopped by the next tick
      if (a.events.filter(([event]) => event === 'shed').length > shedTicks.length) shedTicks.push(i);
    }
    expect(shedTicks[1] - shedTicks[0]).toBe(3);
  });

  it('should shed again once a shed still draining is lost to another platform', async () => {
    const { store, leases, a, queues } = await settled([300, 300, 300, 300, 300, 300]);
    const shedTicks: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      await a.tick(queues, view(queues)); // never stopped: draining
      const sheds = a.events.filter(([event]) => event === 'shed');
      if (sheds.length > shedTicks.length) {
        shedTicks.push(i);
        if (sheds.length === 1) leases.set(sheds[0][1], 'b:other'); // taken over (its lease expired meanwhile)
      }
    }
    expect(a.events.some(([event]) => event === 'lost')).toBe(true);
    expect(shedTicks[1] - shedTicks[0]).toBe(3); // not the 6-tick drain bound
  });

  it('should shed a queue whose ready bytes are under the gap, whatever its messages in flight here', async () => {
    const depths = new Map<string, QueueDepth>([
      ['q1', { ready: 300, unacked: 900 }], // load 1200 (= the gap), ready 300
      ['q2', { ready: 100, unacked: 0 }],
    ]);
    const { store, a, queues } = await settled([1200, 100], depths);
    for (let i = 0; i < 3; i += 1) {
      await store.publishBacklog('b:other', 100, 0);
      await a.tick(queues, view(queues));
    }
    expect(a.events.filter(([event]) => event === 'shed')).toEqual([['shed', 'q1']]); // gap 1200: 300 moves
  });

  it('should take a queue larger than twice its share when it holds nothing, other loads unknown', async () => {
    const { store, legacy } = memoryStore();
    legacy.set('old:1', 0);
    legacy.set('old:2', 0);
    const a = platform('a', store, depthsOf({ q1: 900 }));
    await a.tick(['q1']);
    expect(await a.tick(['q1'])).toEqual(['q1']); // share 300: 450 over it, but a holds nothing
  });

  it('should pick the shed by its ready bytes (what moves), not its messages in flight here', async () => {
    const depths = new Map<string, QueueDepth>([
      ['q1', { ready: 400, unacked: 400 }], // load 800, ready 400
      ['q2', { ready: 500, unacked: 100 }], // load 600, ready 500
      ['q3', { ready: 200, unacked: 0 }],
    ]);
    const { store, a, queues, published } = await settled([800, 500, 200], depths);
    for (let i = 0; i < 3; i += 1) {
      await store.publishBacklog('b:other', 0, 0);
      await a.tick(queues, view(queues));
    }
    // own 1600, gap 1600: by ready bytes q2 (500) is the closest to 800; by load q1 (800) would be
    expect(a.events.filter(([event]) => event === 'shed')).toEqual([['shed', 'q2']]);
    expect(a.details).toContainEqual(['shed', 'q2', { ready_load: 500, own: 1600, share: 800, min_other: 0 }]);
    // published without the shed queue, its messages in flight included (no longer its own)
    expect([...published].find(([node]) => node.startsWith('a:'))?.[1].load).toBe(1000);
  });

  it('should take a queue that waited free for two ticks, over its share and not the least loaded', async () => {
    const depths = ladder([600, 600, 0]);
    const { store, a } = await settled([600, 600], depths);
    const all = ['q1', 'q2', 'q3'];
    const tickA = async () => {
      await store.publishBacklog('b:other', 100, 0); // less loaded than a
      return a.tick(all, view(['q1', 'q2']));
    };
    // a: 1200 of a share of (1200 + 400) / 2 = 800: q3 does not fit, a is not the least loaded
    depths.set('q3', { ready: 400, unacked: 0 });
    expect(await tickA()).not.toContain('q3');
    expect(await tickA()).not.toContain('q3');
    expect(await tickA()).toContain('q3'); // starving
    expect(a.details.find(([event, queue]) => event === 'taken' && queue === 'q3')?.[2]?.starving).toBe(1);
  });

  it('should count the platforms of the previous version live, their load unknown, and stop at its share', async () => {
    const { store, legacy } = memoryStore();
    legacy.set('old:1', 0);
    const depths = ladder([300, 300, 300, 300]);
    const queues = ['q1', 'q2', 'q3', 'q4'];
    const a = platform('a', store, depths);
    await a.tick(queues);
    // share 600 over two live platforms: q1, q2 (450 <= 600) fit, not q3; no known other: not the least loaded
    expect(await a.tick(queues)).toEqual(['q1', 'q2']);
  });

  it('should publish its own load in bytes each tick, and unpublish on release', async () => {
    const depths = bytesOf({ q1: [10, 5000], q2: [10, 3000] });
    const { store, published } = memoryStore();
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    const [token, { load }] = [...published].find(([node]) => node.startsWith('a:')) as [string, { load: number }];
    expect(load).toBe(8000);
    expect((await store.liveBacklogs(30000)).get(token)).toBe(8000);
    await a.lease.release();
    expect((await store.liveBacklogs(30000)).has(token)).toBe(false);
  });

  it('should steal the queue with the most bytes ready, not the most messages', async () => {
    const { store, leases } = memoryStore();
    const depths = bytesOf({ q1: [5000, 5_000_000], q2: [200, 900_000_000] });
    leases.set('q1', 'x:other');
    leases.set('q2', 'y:other');
    const b = platform('b', store, depths);
    await b.tick(['q1', 'q2']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2']); // idle: the largest in bytes
  });

  it('should start a steal under half its share, not above it', async () => {
    // b holds q3; q1 (6000) of another platform is above a share; share = total / 2 live
    const run = async (q3: number) => {
      const { store, leases } = memoryStore();
      const depths = depthsOf({ q1: 6000, q3 });
      leases.set('q1', 'x:other');
      await store.publishBacklog('x:other', 6000, 0);
      const b = platform('b', store, depths);
      await b.tick(['q1', 'q3']);
      await store.publishBacklog('x:other', 6000, 0);
      return b.tick(['q1', 'q3']);
    };
    expect(await run(1500)).toEqual(['q3', 'q1']); // 1500 < 0.5 x 3750
    expect(await run(2200)).toEqual(['q3']); // 2200 > 0.5 x 4100
  });

  it('should not shed at 1.22 x its share, nor while the least loaded is at 0.76 x its share', async () => {
    const run = async (sizes: number[], bLoad: number) => {
      const { store, leases } = memoryStore();
      const depths = ladder(sizes);
      const mine = sizes.slice(0, -1).map((_, i) => `q${i + 1}`);
      const all = [...mine, `q${sizes.length}`];
      const a = platform('a', store, depths);
      for (let i = 0; i < 8; i += 1) await a.tick(mine, view(i < 2 ? [] : mine));
      leases.set(`q${sizes.length}`, 'b:other');
      for (let i = 0; i < 4; i += 1) {
        await store.publishBacklog('b:other', bLoad, 0);
        await a.tick(all, view(mine));
      }
      return a.events.filter(([event]) => event === 'shed').length;
    };
    expect(await run([305, 305, 305, 305, 780], 0)).toBe(0); // 1220 of 1000
    expect(await run([320, 320, 320, 320, 720], 0)).toBe(1); // 1280 of 1000
    expect(await run([400, 400, 400, 400, 400], 760)).toBe(0); // b at 0.76 x 1000
    expect(await run([400, 400, 400, 400, 400], 740)).toBe(1);
  });

  it('should weigh the unsampled part of a queue at the mean of the candidates only', () => {
    const depths = new Map<string, QueueDepth>([
      ['q1', { ready: 10, unacked: 10, bytesReady: 1000, bytesUnacked: 0 }], // unacked not sampled
      ['listen_x', { ready: 1, unacked: 0, bytesReady: 1_000_000, bytesUnacked: 0 }], // not a candidate
    ]);
    const { load, readyLoad } = queueLoads(depths, ['q1']);
    expect(readyLoad('q1')).toBe(1000);
    expect(load('q1')).toBe(2000); // 10 unacked at the 100-byte mean of the candidates
    // the sampled unacked bytes count in the mean too
    const unackedOnly = queueLoads(new Map([['q2', { ready: 10, unacked: 10, bytesReady: 0, bytesUnacked: 1000 }]]), ['q2']);
    expect(unackedOnly.readyLoad('q2')).toBe(1000);
  });

  it('should steal under half its share by default while its own messages are in flight', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500, q2: 20 });
    const a = platform('a', store, depths);
    const b = platform('b', store, depths);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2', 'q1']); // 20 of 260, q1 above a share
    depths.set('q2', { ready: 0, unacked: 20 }); // delivered here: not idle, still under half
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q2: 20 }))).toEqual(['q2', 'q1']);
  });
});

describe('queue lease without the queue depths (task 0040)', () => {
  it('should keep its queues, decide nothing, stop publishing and end its steal while the depths are unread', async () => {
    let clock = 0;
    const { store, leases } = memoryStore(() => clock);
    let down = false;
    const depths = depthsOf({ q1: 500, q2: 20, q3: 300 });
    const read = async () => {
      if (down) throw new Error('management API unreachable');
      return depths;
    };
    const a = platform('a', store, depths, () => clock);
    const b = platform('b', store, depths, () => clock, {}, read);
    await a.tick(['q1', 'q2']);
    await b.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2', 'q1']); // q2 held, q1 stolen
    down = true;
    depths.set('q2', { ready: 0, unacked: 0 });
    for (let i = 0; i < 4; i += 1) {
      clock += 10000;
      await a.tick(['q1', 'q2', 'q3'], view(['q1']));
      expect(await b.tick(['q1', 'q2', 'q3'], view(['q2', 'q1']))).toEqual(['q2']); // kept, no idle release, no steal
    }
    expect(b.events.filter(([event]) => event === 'depths_unread')).toHaveLength(1);
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
    expect(leases.get('q2')?.startsWith('b:')).toBe(true);
    // b no longer live for a: a takes the new queue q3 whatever b's last load
    expect([...(await store.liveBacklogs(30000)).keys()].some((node) => node.startsWith('b:'))).toBe(false);
    expect(leases.get('q3')?.startsWith('a:')).toBe(true);
    // q2 no longer listed: given back, depths still unread
    await b.tick(['q1'], view(['q2']));
    await b.tick(['q1'], view([]));
    expect(leases.has('q2')).toBe(false);
    down = false;
    await b.tick(['q1']);
    expect(b.events.filter(([event]) => event === 'depths_read')).toHaveLength(1);
  });

  it('should restart its tick counts after an outage: a shed needs 3 ticks over after it', async () => {
    let down = false;
    const depths = ladder([300, 300, 300, 300]);
    const { store } = memoryStore();
    const a = platform('a', store, depths, undefined, {}, async () => {
      if (down) throw new Error('management API unreachable');
      return depths;
    });
    const queues = ['q1', 'q2', 'q3', 'q4'];
    for (let i = 0; i < 8; i += 1) await a.tick(queues, view(i < 2 ? [] : queues));
    const over = async () => {
      await store.publishBacklog('b:other', 0, 0);
      await a.tick(queues, view(queues));
    };
    await over();
    await over(); // 2 ticks over
    down = true;
    await over();
    down = false;
    await over();
    await over();
    expect(a.events.some(([event]) => event === 'shed')).toBe(false);
    await over();
    expect(a.events.filter(([event]) => event === 'shed')).toHaveLength(1);
  });

  const outage = (depths: Map<string, QueueDepth>) => {
    let down = false;
    const { store, leases } = memoryStore();
    const a = platform('a', store, depths, undefined, {}, async () => {
      if (down) throw new Error('management API unreachable');
      return depths;
    });
    const tick = async (candidates: string[], consuming: string[]) => {
      await store.publishBacklog('b:other', 100, 0);
      return a.tick(candidates, view(consuming));
    };
    const setDown = (value: boolean) => {
      down = value;
    };
    return { a, leases, tick, setDown };
  };

  it('should restart its idle count after an outage', async () => {
    const depths = depthsOf({ q1: 1000 });
    const { tick, setDown } = outage(depths);
    await tick(['q1'], []);
    expect(await tick(['q1'], [])).toEqual(['q1']);
    depths.set('q1', { ready: 0, unacked: 0 });
    await tick(['q1'], ['q1']); // empty once
    setDown(true);
    await tick(['q1'], ['q1']);
    setDown(false);
    expect(await tick(['q1'], ['q1'])).toEqual(['q1']); // empty a first time again: kept
  });

  it('should restart its free count after an outage', async () => {
    const depths = depthsOf({ q1: 1000, q2: 300, q3: 0 });
    const { leases, tick, setDown } = outage(depths);
    await tick(['q1'], []);
    expect(await tick(['q1'], [])).toEqual(['q1']);
    leases.set('q2', 'b:other');
    // q3 seen free with messages while a is over its share and not the least loaded
    depths.set('q3', { ready: 600, unacked: 0 });
    expect(await tick(['q1', 'q2', 'q3'], ['q1'])).not.toContain('q3');
    setDown(true);
    await tick(['q1', 'q2', 'q3'], ['q1']);
    setDown(false);
    expect(await tick(['q1', 'q2', 'q3'], ['q1'])).not.toContain('q3'); // seen free a first time again
    expect(await tick(['q1', 'q2', 'q3'], ['q1'])).not.toContain('q3');
    expect(await tick(['q1', 'q2', 'q3'], ['q1'])).toContain('q3'); // starving
  });

  it('should leave no queue with messages unconsumed when one platform cannot read the depths (partial outage)', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4', 'q5', 'q6'];
    const c = cluster(ladder([300, 300, 300, 300, 300, 300]), queues);
    c.add('a');
    c.add('b');
    c.add('c');
    for (let i = 0; i < 12; i += 1) await c.round();
    const ofC = c.heldBy('c');
    expect(ofC.length).toBeGreaterThan(0); // c holds load, then goes blind
    c.blind.add('c');
    const shedsBefore = c.count('shed');
    let freeRounds = 0;
    for (let i = 0; i < 20; i += 1) {
      await c.round();
      // a queue with messages left free a round is taken by the next ones (no queue left unconsumed)
      freeRounds = queues.some((queue) => !c.leases.has(queue)) ? freeRounds + 1 : 0;
      expect(freeRounds).toBeLessThanOrEqual(2);
      // counted out at once: no shed toward a platform that takes nothing
      expect([...c.published.keys()].some((node) => node.startsWith('c:'))).toBe(false);
    }
    expect(c.heldBy('c')).toEqual(ofC); // kept, still consumed
    expect(c.count('shed')).toBe(shedsBefore);
  });
});

describe('queue lease rebalancing, review round 2 fixes (task 0040)', () => {
  // a holds the queues, settled (cooldown passed); then the others' loads published at will
  const holder = async (depths: Map<string, QueueDepth>) => {
    const { store, leases, published } = memoryStore();
    const queues = [...depths.keys()];
    const a = platform('a', store, depths);
    for (let i = 0; i < 8; i += 1) await a.tick(queues, view(i < 2 ? [] : queues));
    const over = async (others: Record<string, number>, ticks = 3) => {
      for (let i = 0; i < ticks; i += 1) {
        for (const [node, load] of Object.entries(others)) await store.publishBacklog(node, load, 0);
        await a.tick(queues, view(queues));
      }
      return a.events.filter(([event]) => event === 'shed').map(([, queue]) => queue);
    };
    return { store, leases, published, a, queues, over };
  };

  it('should not shed a queue the least loaded would not take by its own rule (a dominant backfill)', async () => {
    const { over } = await holder(depthsOf({ big: 3000, q1: 200, q2: 200 }));
    // own 3400, share 1133 (three live), gap 3300: big is the closest to half of it, but the least loaded (100)
    // would not take it (100 + 1500 over 1133) and a would be left the least loaded (no shed taken back)
    expect(await over({ 'b:other': 100, 'c:other': 100 })).toEqual(['q1']);
  });

  it('should shed a queue the least loaded takes exactly at its share, not one byte over', async () => {
    // own 2000, share 1000, gap 1400: q1 (800 ready) lands the least loaded (600) at 600 + 400 = 1000, its share
    expect(await (await holder(depthsOf({ q1: 800, q2: 1200 }))).over({ 'b:other': 600 })).toEqual(['q1']);
    // least loaded at 601: 1001 over its share, q2 neither (600 + 600)
    expect(await (await holder(depthsOf({ q1: 800, q2: 1200 }))).over({ 'b:other': 601 })).toEqual([]);
  });

  it('should not shed a queue whose messages in flight here would leave it under the least loaded', async () => {
    const { over } = await holder(new Map([['q1', { ready: 300, unacked: 900 }], ['q2', { ready: 100, unacked: 0 }]]));
    // own 1300, share 650, least loaded 150, gap 1150: q1 moves its 300 ready (the closest to half the gap) but its
    // 900 in flight are answered here then gone, a left at 100 under 150: q2 is shed
    expect(await over({ 'b:other': 150 })).toEqual(['q2']);
  });

  it('should not take a free queue its own consumer still drains, then take it once stopped', async () => {
    const { store } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths);
    await a.tick(['q1']);
    // q1 free with messages, its consumer here still draining (lost, or released while draining)
    const draining = view([], [], { q1: 1 }, ['q1']);
    expect(await a.tick(['q1'], draining)).toEqual([]);
    expect(await a.tick(['q1'], draining)).toEqual([]);
    expect(await a.tick(['q1'], draining)).toEqual([]); // not even starving
    expect(await a.tick(['q1'], view([]))).toEqual(['q1']);
  });

  it('should take its stolen queue at once when it becomes free, its consumer going on', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 5000, q2: 20 });
    leases.set('q1', 'x:other');
    const b = platform('b', store, depths);
    await store.publishBacklog('x:other', 0, 0);
    await b.tick(['q1', 'q2']);
    await store.publishBacklog('x:other', 0, 0);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q2', 'q1']); // q2 taken, q1 stolen (under half its share)
    // q1 given back by x; b at 50: 50 + 2500 over a share of 2525, x less loaded, q1 first seen free
    await store.release('q1', 'x:other');
    depths.set('q2', { ready: 0, unacked: 50 });
    await store.publishBacklog('x:other', 0, 0);
    expect(await b.tick(['q1', 'q2'], view(['q2', 'q1'], [], { q1: 100 }))).toEqual(['q2', 'q1']);
    expect(leases.get('q1')?.startsWith('b:')).toBe(true);
    expect(b.details.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1', { ready: 5000 }], ['steal_stop', 'q1', { taken: 1 }]]);
  });

  it('should end its steal on release', async () => {
    const { store, leases } = memoryStore();
    leases.set('q1', 'x:other');
    const b = platform('b', store, depthsOf({ q1: 5000 }));
    await b.tick(['q1']);
    expect(await b.tick(['q1'])).toEqual(['q1']);
    await b.lease.release();
    expect(b.events.filter(([event]) => event.startsWith('steal'))).toEqual([['steal_start', 'q1'], ['steal_stop', 'q1']]);
    expect(b.lease.current()).toEqual([]);
  });

  it('should unpublish its load at once when the depths become unread', async () => {
    let down = false;
    const { store, published } = memoryStore();
    const depths = depthsOf({ q1: 500 });
    const a = platform('a', store, depths, undefined, {}, async () => {
      if (down) throw new Error('management API unreachable');
      return depths;
    });
    await a.tick(['q1']);
    await a.tick(['q1']);
    expect([...published.keys()].some((node) => node.startsWith('a:'))).toBe(true);
    down = true;
    await a.tick(['q1'], view(['q1']));
    // counted out by the others on their next tick, not one lease TTL later
    expect([...published.keys()].some((node) => node.startsWith('a:'))).toBe(false);
    down = false;
    await a.tick(['q1'], view(['q1']));
    expect([...published.keys()].some((node) => node.startsWith('a:'))).toBe(true);
  });

  it('should publish its message count too, for the platforms of the previous version (rolling deploy)', async () => {
    const { store, published } = memoryStore();
    const depths = new Map<string, QueueDepth>([['q1', { ready: 10, unacked: 5, bytesReady: 5000, bytesUnacked: 2500 }], ['q2', { ready: 3, unacked: 0, bytesReady: 900, bytesUnacked: 0 }]]);
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    const [, mine] = [...published].find(([node]) => node.startsWith('a:')) as [string, { load: number; messages: number }];
    expect(mine.load).toBe(8400);
    expect(mine.messages).toBe(18);
  });

  it('should leave out a platform of unknown load when finding the least loaded', async () => {
    const { store, legacy } = memoryStore();
    legacy.set('old:1', 0);
    await store.publishBacklog('c:other', 5000, 0);
    const a = platform('a', store, ladder([300, 300, 300, 300]));
    const queues = ['q1', 'q2', 'q3', 'q4'];
    await a.tick(queues);
    await store.publishBacklog('c:other', 5000, 0);
    // share 400 over three live: q1 fits, then a is the least loaded of the known loads (5000), not of the unknown one
    expect(await a.tick(queues)).toEqual(queues);
  });

  it('should take beyond its share when as loaded as the least loaded other (a tie)', async () => {
    const { store } = memoryStore();
    await store.publishBacklog('c:other', 300, 0);
    const b = platform('b', store, depthsOf({ q1: 300, q2: 300 }));
    await b.tick(['q1', 'q2']);
    await store.publishBacklog('c:other', 300, 0);
    // share 300: q1 fits, then b at 300 ties with c
    expect(await b.tick(['q1', 'q2'])).toEqual(['q1', 'q2']);
  });

  it('should weigh the unsampled messages at the mean of the candidates only in its decisions', async () => {
    const { store, published } = memoryStore();
    const depths = new Map<string, QueueDepth>([
      ['q1', { ready: 10, unacked: 0 }], // not sampled yet
      ['q2', { ready: 10, unacked: 0, bytesReady: 1000, bytesUnacked: 0 }],
      ['listen_x', { ready: 1, unacked: 0, bytesReady: 1_000_000, bytesUnacked: 0 }], // not a candidate
    ]);
    const a = platform('a', store, depths);
    await a.tick(['q1', 'q2']);
    await a.tick(['q1', 'q2']);
    expect([...published].find(([node]) => node.startsWith('a:'))?.[1].load).toBe(2000);
  });

  it('should end a steal when alone once its own queues have messages ready, whatever its share', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 5000, q2: 0 });
    leases.set('q1', 'x:blind'); // held by a platform not live (its depths unread)
    const b = platform('b', store, depths);
    await b.tick(['q1', 'q2']);
    expect(await b.tick(['q1', 'q2'])).toEqual(['q1']); // idle: stolen
    depths.set('q2', { ready: 10, unacked: 0 });
    expect(await b.tick(['q1', 'q2'], view(['q1'], [], { q1: 100 }))).toEqual(['q2']); // alone: no share to stay under
  });

  it('should not shed and take back the dominant queue of a backfill in a cluster', async () => {
    const queues = ['q1', 'q2', 'q3', 'q4', 'q5', 'q6'];
    const depths = ladder([300, 300, 300, 300, 300, 300]);
    const c = cluster(depths, queues);
    c.add('a');
    c.add('b');
    c.add('c');
    for (let i = 0; i < 12; i += 1) await c.round();
    // a backfill on one queue, with messages in flight at its holder
    const [backfill] = c.heldBy('a');
    depths.set(backfill, { ready: 3000, unacked: 600 });
    for (let i = 0; i < 40; i += 1) await c.round();
    const sheds = [...c.nodes.values()].flatMap(({ p }) => p.events.filter(([event, queue]) => event === 'shed' && queue === backfill));
    expect(sheds).toEqual([]);
    expect(c.leases.get(backfill)?.startsWith('a:')).toBe(true);
  });
});

describe('queue lease with a drain that never ends, review round 3 fixes (task 0040)', () => {
  it('should not steal a queue its own consumer still drains, nor take it once free', async () => {
    const { store, leases } = memoryStore();
    const depths = depthsOf({ q1: 5000 });
    leases.set('q1', 'x:other');
    const b = platform('b', store, depths);
    await store.publishBacklog('x:other', 5000, 0);
    await b.tick(['q1']);
    await store.publishBacklog('x:other', 5000, 0);
    // a message of q1 hangs here since an earlier steal: its consumer stays stopping, never consumes it again
    const draining = view([], [], { q1: 1 }, ['q1']);
    expect(await b.tick(['q1'], draining)).toEqual([]); // idle, but not stolen
    await store.release('q1', 'x:other');
    await store.publishBacklog('x:other', 0, 0);
    expect(await b.tick(['q1'], draining)).toEqual([]);
    expect(leases.has('q1')).toBe(false);
    expect(b.events.filter(([event]) => event === 'steal_start' || event === 'taken')).toEqual([]);
  });

  it('should enter the degraded mode once even when Redis refuses its unpublish', async () => {
    const { store } = memoryStore();
    const failing: LeaseStore = { ...store, unpublish: () => Promise.reject(new Error('redis down')) };
    const p = platform('a', failing, depthsOf({ q1: 500 }), undefined, {}, () => Promise.reject(new Error('management API unreachable')));
    await p.tick(['q1']);
    await p.tick(['q1']);
    expect(p.events.filter(([event]) => event === 'depths_unread')).toHaveLength(1);
  });

  // b holds q1 (ready, movable) and q2 (in flight, not movable); a joins with a message of q1 stuck on it: a refuses
  // q1 (still draining), b sheds it, it starves, b takes it back
  const stuckCluster = async () => {
    const depths = new Map<string, QueueDepth>([['q1', { ready: 1000, unacked: 0 }], ['q2', { ready: 50, unacked: 3000 }]]);
    const c = cluster(depths, ['q1', 'q2']);
    c.add('b');
    for (let i = 0; i < 3; i += 1) await c.round();
    c.add('a', ['q1']);
    let gap = 0;
    let maxGap = 0;
    let unconsumed = 0;
    for (let i = 0; i < 60; i += 1) {
      await c.round();
      gap = c.consumedBySomeone('q1') ? 0 : gap + 1;
      unconsumed += gap > 0 ? 1 : 0;
      maxGap = Math.max(maxGap, gap);
    }
    const sheds = (c.nodes.get('b')?.p.events ?? []).filter(([event, queue]) => event === 'shed' && queue === 'q1').length;
    return { c, maxGap, unconsumed, sheds };
  };

  it('should leave no queue with messages unconsumed for a cooldown when a platform drains it forever', async () => {
    const { c, maxGap } = await stuckCluster();
    expect(maxGap).toBeLessThanOrEqual(6);
    expect(c.leases.get('q1')?.startsWith('a:')).toBe(false); // never held by the platform that cannot consume it
  });

  it('should not shed again for a while a queue it took back because the least loaded could not take it', async () => {
    const { c, sheds, unconsumed } = await stuckCluster();
    // 60 ticks: shed, starving take-back 3 ticks later, then no new shed for 5 x K ticks (not one every K + 3 ticks)
    expect(sheds).toBeLessThanOrEqual(2);
    expect(unconsumed).toBeLessThanOrEqual(6);
    const taken = (c.nodes.get('b')?.p.details ?? []).filter(([event, queue]) => event === 'taken' && queue === 'q1');
    expect(taken.at(-1)?.[2]).toMatchObject({ starving: 1 });
  });
});
