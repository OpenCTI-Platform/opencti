import conf, { logApp } from '../../config/conf';

/**
 * Bounded, fair scheduler for the playbook executions started by the stream, PIR and cron triggers.
 *
 * A playbook step can wait for minutes (an AI agent step calls XTM One for up to 10 minutes,
 * with retries). The trigger loops used to await every execution in turn, so one slow step
 * stopped the trigger processing of every other playbook.
 *
 * - Executions are kept in one FIFO lane per playbook: the executions of one playbook still run
 *   one after the other, in the order of their events, as before.
 * - Lanes run in parallel, at most `maxConcurrency` at once on this node, started round-robin
 *   across playbooks, so a playbook with slow steps never holds back the others.
 * - Memory stays bounded: at most `maxPending` executions are queued or running; past it,
 *   `waitForCapacity` waits (backpressure on the stream, nothing is dropped).
 * - `run` resolves when the execution has ended (success or error, errors are logged), never rejects.
 */
export type TriggerSchedulerOptions = {
  maxConcurrency: number;
  maxPending?: number;
};

type TriggerTask = () => Promise<unknown>;
type QueuedTrigger = { task: TriggerTask; logMeta: Record<string, unknown>; resolve: () => void };

export const createTriggerScheduler = (name: string, options: TriggerSchedulerOptions) => {
  const limit = Math.max(1, Math.floor(options.maxConcurrency));
  const maxPending = Math.max(limit, Math.floor(options.maxPending ?? 1000));
  let running = 0;
  let pending = 0; // queued + running
  const runningLanes = new Set<string>();
  // Insertion order of the Map is the round-robin order: a lane served is moved to the end.
  const lanes = new Map<string, QueuedTrigger[]>();
  let capacityWaiters: Array<() => void> = [];
  let idleWaiters: Array<() => void> = [];
  let backpressureLogged = false;

  let dispatch: () => void = () => {};

  const settle = () => {
    pending -= 1;
    if (pending < maxPending && capacityWaiters.length > 0) {
      const waiters = capacityWaiters;
      capacityWaiters = [];
      waiters.forEach((resolve) => resolve());
    }
    if (pending === 0 && idleWaiters.length > 0) {
      const waiters = idleWaiters;
      idleWaiters = [];
      waiters.forEach((resolve) => resolve());
    }
  };

  const start = (key: string, item: QueuedTrigger) => {
    running += 1;
    runningLanes.add(key);
    // Detached on purpose: the trigger loop never waits for the execution.
    void (async () => {
      try {
        await item.task();
      } catch (error) {
        logApp.error(`[OPENCTI-MODULE] Playbook manager ${name} execution error`, { cause: error, manager: 'PLAYBOOK_MANAGER', ...item.logMeta });
      } finally {
        running -= 1;
        runningLanes.delete(key);
        settle();
        item.resolve();
        dispatch();
      }
    })();
  };

  dispatch = () => {
    let started = true;
    while (running < limit && started) {
      started = false;
      const keys = Array.from(lanes.keys());
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        if (!runningLanes.has(key)) {
          const lane = lanes.get(key) as QueuedTrigger[];
          const next = lane.shift() as QueuedTrigger;
          // Round-robin: the lane just served goes to the end of the rotation.
          lanes.delete(key);
          if (lane.length > 0) {
            lanes.set(key, lane);
          }
          start(key, next);
          started = true;
          break;
        }
      }
    }
  };

  // Backpressure: resolves at once while fewer than maxPending executions are queued or running.
  const waitForCapacity = async () => {
    while (pending >= maxPending) {
      if (!backpressureLogged) {
        backpressureLogged = true;
        logApp.warn(`[OPENCTI-MODULE] Playbook manager ${name} executions are at capacity, waiting`, { manager: 'PLAYBOOK_MANAGER', running, pending, maxPending });
      }
      await new Promise<void>((resolve) => {
        capacityWaiters.push(resolve);
      });
    }
    backpressureLogged = false;
  };

  // A lane with an execution queued or running.
  const busy = (playbookId: string) => runningLanes.has(playbookId) || lanes.has(playbookId);

  // Queues the execution in the lane of its playbook; the promise resolves when it has ended.
  const run = (playbookId: string, task: TriggerTask, logMeta: Record<string, unknown> = {}): Promise<void> => {
    pending += 1;
    return new Promise<void>((resolve) => {
      const item = { task, logMeta: { playbookId, ...logMeta }, resolve };
      const lane = lanes.get(playbookId) ?? [];
      lane.push(item);
      if (!lanes.has(playbookId)) {
        lanes.set(playbookId, lane);
      }
      dispatch();
    });
  };

  // Resolves when nothing is queued or running.
  const idle = async () => {
    if (pending === 0) {
      return;
    }
    await new Promise<void>((resolve) => {
      idleWaiters.push(resolve);
    });
  };

  return {
    run,
    busy,
    waitForCapacity,
    idle,
    running: () => running,
    pending: () => pending,
  };
};

export type TriggerScheduler = ReturnType<typeof createTriggerScheduler>;

/**
 * Stream position tracker: the manager stream position is saved only up to the last event whose
 * executions have all ended, in event order, so the saved position never moves past an event
 * whose execution is still running, as when the stream handler awaited every execution.
 */
export const createEventWatermark = (commit: (eventId: string) => Promise<unknown>) => {
  // Insertion order of the Map is the event order.
  const entries = new Map<string, { pending: number; closed: boolean }>();
  let commitChain: Promise<void> = Promise.resolve();
  let stopped = false;

  const flush = () => {
    let last: string | undefined;
    for (const [id, entry] of entries) {
      if (!entry.closed || entry.pending > 0) {
        break;
      }
      entries.delete(id);
      last = id;
    }
    if (last && !stopped) {
      const eventId = last;
      commitChain = commitChain.then(async () => {
        await commit(eventId);
      }).catch((error) => {
        logApp.error('[OPENCTI-MODULE] Playbook manager stream position save error', { cause: error, manager: 'PLAYBOOK_MANAGER', eventId });
      });
    }
  };

  return {
    open: (eventId: string) => {
      entries.set(eventId, { pending: 0, closed: false });
    },
    track: (eventId: string, done: Promise<void>) => {
      const entry = entries.get(eventId);
      if (!entry) return;
      entry.pending += 1;
      void done.finally(() => {
        entry.pending -= 1;
        flush();
      });
    },
    close: (eventId: string) => {
      const entry = entries.get(eventId);
      if (entry) {
        entry.closed = true;
      }
      flush();
    },
    // Once the stream processor of this node stops, the position is never saved again: another
    // node may hold the manager lock and be further, the events not saved yet are processed again.
    stop: () => {
      stopped = true;
    },
    settled: () => commitChain,
    tracked: () => entries.size,
  };
};

export type EventWatermark = ReturnType<typeof createEventWatermark>;

const PLAYBOOK_TRIGGER_MAX_CONCURRENCY: number = conf.get('playbook_manager:trigger_max_concurrency') || 10;
const PLAYBOOK_TRIGGER_MAX_PENDING: number = conf.get('playbook_manager:trigger_max_pending') || 1000;

// One scheduler per node, shared by the stream, PIR and cron triggers.
export const playbookTriggerScheduler = createTriggerScheduler('trigger', {
  maxConcurrency: PLAYBOOK_TRIGGER_MAX_CONCURRENCY,
  maxPending: PLAYBOOK_TRIGGER_MAX_PENDING,
});
