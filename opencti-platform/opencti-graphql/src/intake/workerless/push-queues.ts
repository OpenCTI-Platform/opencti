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
