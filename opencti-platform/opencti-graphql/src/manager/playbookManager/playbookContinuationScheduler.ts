import { ValueType } from '@opentelemetry/api';
import conf, { logApp } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { meterManager } from '../../config/tracing';

/**
 * Bounded, fair scheduler for the playbook steps that follow an external callback.
 *
 * When a connector step calls back (`playbookStepExecution`), the rest of the chain
 * (AI transforms, ingestion, notifications...) is run in the background so the
 * connector is acknowledged as soon as its bundle is accepted.
 *
 * - The request path never waits for a slot: `schedule` queues the continuation and returns
 *   at once. A continuation starts when a slot is free.
 * - At most `maxConcurrency` continuations run at once on this node, and at most
 *   `maxConcurrencyPerPlaybook` of them for one playbook, so a playbook with slow steps
 *   (AI agent calls) cannot take every slot.
 * - Queued continuations are kept per playbook and started round-robin across playbooks,
 *   so a short chain of one playbook is never held behind the backlog of another.
 * - The backlog is bounded: when `maxWaiting` continuations are queued, `assertAccepting`
 *   throws, so the callback is refused and the connector sees the error. A refused
 *   callback never runs later.
 */
export type ContinuationSchedulerOptions = {
  maxConcurrency: number;
  maxConcurrencyPerPlaybook?: number;
  maxWaiting?: number;
};

type ContinuationTask = () => Promise<void>;
type QueuedContinuation = { task: ContinuationTask; logMeta: Record<string, unknown> };

const DEFAULT_PLAYBOOK_KEY = '__no_playbook__';

export const createContinuationScheduler = (options: ContinuationSchedulerOptions) => {
  const limit = Math.max(1, Math.floor(options.maxConcurrency));
  const perPlaybookLimit = Math.min(limit, Math.max(1, Math.floor(options.maxConcurrencyPerPlaybook ?? limit)));
  const maxWaiting = Math.max(0, Math.floor(options.maxWaiting ?? 1000));
  let running = 0;
  let waiting = 0;
  const runningByPlaybook = new Map<string, number>();
  // Insertion order of the Map is the round-robin order: a playbook served is moved to the end.
  const queues = new Map<string, QueuedContinuation[]>();
  let saturationLogged = false;

  // Assigned below: start() and dispatch() call each other.
  let dispatch: () => void = () => {};

  const playbookKey = (logMeta: Record<string, unknown>) => (typeof logMeta.playbookId === 'string' ? logMeta.playbookId : DEFAULT_PLAYBOOK_KEY);

  const start = (key: string, continuation: QueuedContinuation) => {
    running += 1;
    runningByPlaybook.set(key, (runningByPlaybook.get(key) ?? 0) + 1);
    // Detached on purpose: the caller never waits for the task.
    void (async () => {
      try {
        await continuation.task();
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Playbook manager continuation error', { cause: error, manager: 'PLAYBOOK_MANAGER', ...continuation.logMeta });
      } finally {
        running -= 1;
        const left = (runningByPlaybook.get(key) ?? 1) - 1;
        if (left <= 0) {
          runningByPlaybook.delete(key);
        } else {
          runningByPlaybook.set(key, left);
        }
        dispatch();
      }
    })();
  };

  dispatch = () => {
    let started = true;
    while (running < limit && started) {
      started = false;
      const keys = Array.from(queues.keys());
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        const queue = queues.get(key) as QueuedContinuation[];
        if ((runningByPlaybook.get(key) ?? 0) < perPlaybookLimit) {
          const next = queue.shift() as QueuedContinuation;
          waiting -= 1;
          // Round-robin: the playbook just served goes to the end of the rotation.
          queues.delete(key);
          if (queue.length > 0) {
            queues.set(key, queue);
          }
          start(key, next);
          started = true;
          break;
        }
      }
    }
    if (waiting === 0 && saturationLogged) {
      saturationLogged = false;
      logApp.info('[OPENCTI-MODULE] Playbook manager continuation backlog drained', { manager: 'PLAYBOOK_MANAGER', running });
    }
  };

  // Called on the request path BEFORE the connector step is registered, so a refused
  // callback leaves no trace of an accepted step and never runs later.
  const assertAccepting = (logMeta: Record<string, unknown> = {}) => {
    if (waiting >= maxWaiting) {
      logApp.warn('[OPENCTI-MODULE] Playbook manager continuation refused, backlog full', { manager: 'PLAYBOOK_MANAGER', running, waiting, maxWaiting, ...logMeta });
      throw UnsupportedError('Playbook continuation backlog is full on this node, retry later', { running, waiting, max_waiting: maxWaiting });
    }
  };

  // Resolves at once: the continuation is started now if a slot is free, else queued.
  const schedule = async (task: ContinuationTask, logMeta: Record<string, unknown> = {}) => {
    const key = playbookKey(logMeta);
    const continuation = { task, logMeta };
    if (running < limit && (runningByPlaybook.get(key) ?? 0) < perPlaybookLimit && !queues.has(key)) {
      start(key, continuation);
      return;
    }
    const queue = queues.get(key) ?? [];
    queue.push(continuation);
    queues.set(key, queue);
    waiting += 1;
    if (!saturationLogged) {
      saturationLogged = true;
      logApp.warn('[OPENCTI-MODULE] Playbook manager continuations are waiting for a slot', {
        manager: 'PLAYBOOK_MANAGER', running, waiting, maxConcurrency: limit, maxConcurrencyPerPlaybook: perPlaybookLimit, ...logMeta,
      });
    }
  };

  return {
    assertAccepting,
    schedule,
    running: () => running,
    waiting: () => waiting,
    runningFor: (playbookId: string) => runningByPlaybook.get(playbookId) ?? 0,
  };
};

const PLAYBOOK_CONTINUATION_MAX_CONCURRENCY: number = conf.get('playbook_manager:callback_continuation_max_concurrency') || 10;
const PLAYBOOK_CONTINUATION_MAX_CONCURRENCY_PER_PLAYBOOK: number = conf.get('playbook_manager:callback_continuation_max_concurrency_per_playbook') || 3;
const PLAYBOOK_CONTINUATION_MAX_WAITING: number = conf.get('playbook_manager:callback_continuation_max_waiting') ?? 1000;

export const playbookContinuationScheduler = createContinuationScheduler({
  maxConcurrency: PLAYBOOK_CONTINUATION_MAX_CONCURRENCY,
  maxConcurrencyPerPlaybook: PLAYBOOK_CONTINUATION_MAX_CONCURRENCY_PER_PLAYBOOK,
  maxWaiting: PLAYBOOK_CONTINUATION_MAX_WAITING,
});

// Saturation is visible as metrics of this node.
const meter = meterManager.meterProvider.getMeter('opencti-playbook');
meter.createObservableGauge('opencti_playbook_continuation_running', {
  valueType: ValueType.INT,
  description: 'Playbook continuations running on this node after a connector callback',
}).addCallback((result) => result.observe(playbookContinuationScheduler.running()));
meter.createObservableGauge('opencti_playbook_continuation_waiting', {
  valueType: ValueType.INT,
  description: 'Playbook continuations waiting for a slot on this node after a connector callback',
}).addCallback((result) => result.observe(playbookContinuationScheduler.waiting()));
