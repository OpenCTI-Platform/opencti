// The push queues a platform consumes (worker-less intake POC, task 0040 multi-platform step 1).
// With app:ingestion_sequencer:multi_writer every platform runs its own intake: the connector push
// queues are consumed by all of them (RabbitMQ gives each message to one consumer, as with the
// workers). The queues of the stream synchronizations carry ordered events (create, update,
// delete, merge of the same entities, syncManager.js): one platform at a time consumes them, the
// one holding the intake's historical lock, re-elected by the manager's cron on failover.

export const intakeLockKey = (base: string, multiWriter: boolean, nodeId: string) => (multiWriter ? `${base}_${nodeId}` : base);

export const consumedPushQueues = (queues: string[], orderedQueues: Set<string>, consumesOrdered: boolean) => (
  consumesOrdered ? queues : queues.filter((queue) => !orderedQueues.has(queue))
);

export interface HeldLock {
  signal: AbortSignal;
  unlock: () => Promise<void>;
}

// The right to consume the ordered queues. Once lost (its lock signal aborted), the consumer is
// declared dead: its channels on the ordered queues cannot be given back one by one, the cron
// starts the intake again and the platform competes for the lock again.
export interface OrderedQueuesLeadership {
  // Tries to take the lock when not held; true while this platform holds it
  refresh: () => Promise<boolean>;
  lost: () => boolean;
  release: () => Promise<void>;
}

export const createOrderedQueuesLeadership = (tryLock: () => Promise<HeldLock | null>): OrderedQueuesLeadership => {
  let held: HeldLock | null = null;
  let lost = false;
  return {
    refresh: async () => {
      if (lost) return false;
      if (held) {
        if (held.signal.aborted) {
          lost = true;
          return false;
        }
        return true;
      }
      held = await tryLock();
      return held !== null;
    },
    lost: () => lost,
    release: async () => {
      const current = held;
      held = null;
      if (current) await current.unlock();
    },
  };
};

// task 0040 queue affinity test (multi_writer): groups of connector name fragments, `|` between groups
// and `,` inside one (`connector-07,connector-05|connector-01,connector-02`). A platform holding the
// slot of a group consumes the push queues of that group's connectors and of the connectors of no
// group; the queues of the other groups are left to the platforms holding their slots.
// Test knob only, not kept (the dynamic lease, queue-lease.ts, replaces it): a platform holds one slot and
// never takes a free one, so the group of a dead platform waits for another platform to start, and a
// fragment matches any name containing it (`connector-1` also matches `connector-10`).
export const parseQueuePartition = (spec: string | undefined): string[][] => (spec ?? '')
  .split('|')
  .map((group) => group.split(',').map((fragment) => fragment.trim()).filter((fragment) => fragment.length > 0))
  .filter((group) => group.length > 0);

export const partitionedPushQueues = (connectors: { name?: string; queue: string }[], groups: string[][], slot: number | null): string[] => {
  const groupOf = (name: string) => groups.findIndex((group) => group.some((fragment) => name.includes(fragment)));
  const queues = connectors.filter(({ name }) => {
    const group = groupOf(name ?? '');
    return group === -1 || group === slot;
  }).map(({ queue }) => queue);
  return [...new Set(queues)];
};

// The slot (group index) this platform holds: the first free one among `count`, each a lock. Once
// lost (lock signal aborted), the consumer is declared dead like on the ordered queues and the cron
// starts the intake again.
export interface PartitionSlot {
  refresh: () => Promise<number | null>;
  lost: () => boolean;
  release: () => Promise<void>;
}

export const createPartitionSlot = (count: number, tryLock: (slot: number) => Promise<HeldLock | null>): PartitionSlot => {
  let held: { slot: number; lock: HeldLock } | null = null;
  let lost = false;
  return {
    refresh: async () => {
      if (lost) return null;
      if (held) {
        if (held.lock.signal.aborted) {
          lost = true;
          return null;
        }
        return held.slot;
      }
      for (let slot = 0; slot < count; slot += 1) {
        const lock = await tryLock(slot);
        if (lock) {
          held = { slot, lock };
          return slot;
        }
      }
      return null;
    },
    lost: () => lost,
    release: async () => {
      const current = held;
      held = null;
      if (current) await current.lock.unlock();
    },
  };
};

// task 0040 (lease or partition): a failed listing (Redis, the connectors) keeps the queues of the last one,
// for at most maxMs since the last success: past it (a lease not renewed for its TTL is lost, another platform
// may consume its queues) the failure ends the consumer, which drains and is started again. Never before a
// first success.
export const keepLastQueuesOnFailure = (
  listOnce: () => Promise<string[]>,
  maxMs: number,
  onKept: (cause: unknown) => void,
  now: () => number = Date.now,
): (() => Promise<string[]>) => {
  let last: string[] | null = null;
  let lastAt = 0;
  return async () => {
    try {
      last = await listOnce();
      lastAt = now();
      return last;
    } catch (cause) {
      if (last === null || now() - lastAt >= maxMs) throw cause;
      onKept(cause);
      return last;
    }
  };
};

// task 0040: the push queues of the synchronizations (consumed in order), as last read; null before a first read.
// `read` throws on failure; `refresh` keeps the last ones, told once per outage.
export const createOrderedQueuesReader = (
  readOnce: () => Promise<Set<string>>,
  onUnread: (cause: unknown) => void,
  onReadAgain: () => void,
) => {
  let known: Set<string> | null = null;
  let unread = false;
  const read = async () => {
    known = await readOnce();
    if (unread) onReadAgain();
    unread = false;
    return known;
  };
  return {
    known: () => known,
    read,
    refresh: async () => {
      try {
        await read();
      } catch (cause) {
        if (!unread) onUnread(cause);
        unread = true;
      }
    },
  };
};
