import { v4 as uuidv4 } from 'uuid';

// task 0040 dynamic queue lease (multi_writer): each connector push queue is consumed by the platform
// holding its lease in Redis, so that the platforms write disjoint connectors and share fewer lock
// keys. On each tick of the manager a platform renews its leases, gives back the queues empty for
// `releaseIdleTicks` ticks, and takes the free queues holding messages, the largest first, while its
// own backlog is under its share (total backlog / live platforms). A platform left without messages
// ready joins, as a second consumer, the queue of another platform holding the largest backlog (work
// stealing) until that queue is empty or it takes a queue of its own; never a queue that carried
// events, consumed in order by its holder. A lease is a hint, not a guard: two consumers on a queue
// is the sharing without lease, slower only. The ordered queues of the synchronizations stay out of
// it (push-queues.ts leadership).

export interface QueueDepth {
  ready: number;
  unacked: number;
}

export interface LeaseStore {
  // Extends the lease while held by the token, takes it back when it expired free; false when another holds it
  renew: (queue: string, token: string, ttlMs: number) => Promise<boolean>;
  acquire: (queue: string, token: string, ttlMs: number) => Promise<boolean>;
  release: (queue: string, token: string) => Promise<boolean>;
  holders: (queues: string[]) => Promise<Map<string, string | null>>;
  publishBacklog: (token: string, backlog: number) => Promise<void>;
  // The backlog published by each live platform (self included): published within the last ttlMs
  liveBacklogs: (ttlMs: number) => Promise<Map<string, number>>;
  markOrdered: (queues: string[]) => Promise<void>;
  ordered: (queues: string[]) => Promise<Set<string>>;
}

// What the platform's consumer knows of a queue
export interface ConsumerView {
  // An event message was consumed from it: its holder consumes it in order
  isOrdered: (queue: string) => boolean;
  // Its channel is open (a stopped queue is drained and closed)
  isConsuming: (queue: string) => boolean;
}

export type LeaseEvent = 'taken' | 'released' | 'lost' | 'steal_start' | 'steal_stop';

export interface QueueLeaseOptions {
  ttlMs: number;
  // Messages ready on the queue of another platform before joining it
  stealBacklogMin: number;
  releaseIdleTicks: number;
}

export interface QueueLease {
  renew: () => Promise<void>;
  // The queues to consume among the candidates
  assign: (candidates: string[], consumer: ConsumerView) => Promise<string[]>;
  // The queues consumed without a new decision (queue depths unavailable)
  current: () => string[];
  release: () => Promise<void>;
}

export const createQueueLease = (
  nodeId: string,
  store: LeaseStore,
  readDepths: () => Promise<Map<string, QueueDepth>>,
  options: QueueLeaseOptions,
  onEvent: (event: LeaseEvent, queue: string) => void,
): QueueLease => {
  // A restarted platform keeps its node id but never renews the leases of its previous run
  const token = `${nodeId}:${uuidv4()}`;
  const held = new Set<string>();
  // Given back once its consumer is stopped: renewed until then, so no other platform takes it while
  // its messages in flight are still written
  const releasing = new Set<string>();
  const idleTicks = new Map<string, number>();
  let stealing: string | null = null;
  let first = true;
  const current = () => [...held, ...(stealing ? [stealing] : [])];
  const lose = (queue: string) => {
    held.delete(queue);
    releasing.delete(queue);
    idleTicks.delete(queue);
    onEvent('lost', queue);
  };
  return {
    renew: async () => {
      for (const queue of [...held, ...releasing]) {
        if (!await store.renew(queue, token, options.ttlMs)) lose(queue);
      }
    },
    assign: async (candidates, consumer) => {
      const depths = await readDepths();
      const ready = (queue: string) => depths.get(queue)?.ready ?? 0;
      const backlog = (queue: string) => ready(queue) + (depths.get(queue)?.unacked ?? 0);
      const listed = new Set(candidates);
      // Released: drained queues, then empty (or no longer listed) held ones
      for (const queue of [...releasing]) {
        if (!consumer.isConsuming(queue)) {
          releasing.delete(queue);
          await store.release(queue, token);
          onEvent('released', queue);
        }
      }
      for (const queue of [...held]) {
        const ticks = backlog(queue) === 0 ? (idleTicks.get(queue) ?? 0) + 1 : 0;
        idleTicks.set(queue, ticks);
        if (!listed.has(queue) || ticks >= options.releaseIdleTicks) {
          held.delete(queue);
          idleTicks.delete(queue);
          releasing.add(queue);
        }
      }
      const orderedHeld = [...held].filter(consumer.isOrdered);
      if (orderedHeld.length > 0) await store.markOrdered(orderedHeld);
      let own = [...held].reduce((sum, queue) => sum + backlog(queue), 0);
      // The first tick only announces the platform: the others count it in their share before it takes
      if (first) {
        first = false;
        await store.publishBacklog(token, own);
        return current();
      }
      const live = await store.liveBacklogs(options.ttlMs);
      live.set(token, own);
      const total = candidates.reduce((sum, queue) => sum + backlog(queue), 0);
      const share = total / live.size;
      const others = [...live].filter(([node]) => node !== token).map(([, value]) => value);
      const minOther = others.length > 0 ? Math.min(...others) : Infinity;
      const holders = await store.holders(candidates);
      const free = candidates
        .filter((queue) => !holders.get(queue) && !releasing.has(queue) && backlog(queue) > 0)
        .sort((a, b) => backlog(b) - backlog(a));
      for (const queue of free) {
        // Up to its share; the least loaded platform takes beyond it, so that no queue is left unconsumed
        if (own > 0 && own >= share && own > minOther) break;
        if (await store.acquire(queue, token, options.ttlMs)) {
          held.add(queue);
          own += backlog(queue);
          onEvent('taken', queue);
        }
      }
      await store.publishBacklog(token, own);
      let target: string | null = null;
      if ([...held].every((queue) => ready(queue) === 0)) {
        const othersQueues = candidates.filter((queue) => !held.has(queue) && !releasing.has(queue) && !!holders.get(queue) && holders.get(queue) !== token);
        const marked = othersQueues.length > 0 ? await store.ordered(othersQueues) : new Set<string>();
        const stealable = othersQueues.filter((queue) => !marked.has(queue) && !consumer.isOrdered(queue));
        if (stealing && stealable.includes(stealing) && ready(stealing) > 0) {
          target = stealing;
        } else {
          const best = stealable.filter((queue) => ready(queue) >= options.stealBacklogMin).sort((a, b) => ready(b) - ready(a))[0];
          target = best ?? null;
        }
      }
      if (target !== stealing) {
        if (stealing) onEvent('steal_stop', stealing);
        if (target) onEvent('steal_start', target);
        stealing = target;
      }
      return current();
    },
    current,
    release: async () => {
      const queues = [...held, ...releasing];
      held.clear();
      releasing.clear();
      stealing = null;
      for (const queue of queues) await store.release(queue, token);
    },
  };
};
