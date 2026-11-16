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
 * - The continuations live in the memory of this node. `drain` is called when the node stops:
 *   new callbacks are refused (`assertAccepting` throws, the connector sees the error), the
 *   queued continuations are not started, the running ones get a bounded wait, and every
 *   continuation that cannot end is reported through its `onAbandon` (an error observation on
 *   the playbook execution) with a log line, so a stop never loses a chain silently.
 */
export type ContinuationSchedulerOptions = {
  maxConcurrency: number;
  maxConcurrencyPerPlaybook?: number;
  maxWaiting?: number;
};

export type ContinuationAbandonReason = 'shutdown_timeout' | 'shutdown_before_start';
export type ContinuationAbandonFn = (reason: ContinuationAbandonReason) => Promise<void>;

type ContinuationTask = () => Promise<void>;
type QueuedContinuation = { task: ContinuationTask; logMeta: Record<string, unknown>; onAbandon?: ContinuationAbandonFn };
type InFlight = { done: Promise<void>; continuation: QueuedContinuation };

const DEFAULT_PLAYBOOK_KEY = '__no_playbook__';

export const createContinuationScheduler = (options: ContinuationSchedulerOptions) => {
  const limit = Math.max(1, Math.floor(options.maxConcurrency));
  const perPlaybookLimit = Math.min(limit, Math.max(1, Math.floor(options.maxConcurrencyPerPlaybook ?? limit)));
  const maxWaiting = Math.max(0, Math.floor(options.maxWaiting ?? 1000));
  let running = 0;
  let waiting = 0;
  let draining = false;
  const runningByPlaybook = new Map<string, number>();
  // Insertion order of the Map is the round-robin order: a playbook served is moved to the end.
  const queues = new Map<string, QueuedContinuation[]>();
  const inFlight = new Set<InFlight>();
  let saturationLogged = false;

  // Assigned below: start() and dispatch() call each other.
  let dispatch: () => void = () => {};

  const playbookKey = (logMeta: Record<string, unknown>) => (typeof logMeta.playbookId === 'string' ? logMeta.playbookId : DEFAULT_PLAYBOOK_KEY);

  const reportAbandon = async (continuation: QueuedContinuation, reason: ContinuationAbandonReason) => {
    logApp.error('[OPENCTI-MODULE] Playbook manager continuation interrupted by the platform stop', { manager: 'PLAYBOOK_MANAGER', reason, ...continuation.logMeta });
    if (continuation.onAbandon) {
      try {
        await continuation.onAbandon(reason);
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Playbook manager cannot register an interrupted continuation', { cause: error, manager: 'PLAYBOOK_MANAGER', reason, ...continuation.logMeta });
      }
    }
  };

  const start = (key: string, continuation: QueuedContinuation) => {
    running += 1;
    runningByPlaybook.set(key, (runningByPlaybook.get(key) ?? 0) + 1);
    const entry: InFlight = { done: Promise.resolve(), continuation };
    inFlight.add(entry);
    // Detached on purpose: the caller never waits for the task.
    entry.done = (async () => {
      try {
        await continuation.task();
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Playbook manager continuation error', { cause: error, manager: 'PLAYBOOK_MANAGER', ...continuation.logMeta });
      } finally {
        inFlight.delete(entry);
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
    while (!draining && running < limit && started) {
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
    if (draining) {
      logApp.warn('[OPENCTI-MODULE] Playbook manager continuation refused, the platform is stopping', { manager: 'PLAYBOOK_MANAGER', ...logMeta });
      throw UnsupportedError('Playbook continuation refused, the platform is stopping, retry later');
    }
    if (waiting >= maxWaiting) {
      logApp.warn('[OPENCTI-MODULE] Playbook manager continuation refused, backlog full', { manager: 'PLAYBOOK_MANAGER', running, waiting, maxWaiting, ...logMeta });
      throw UnsupportedError('Playbook continuation backlog is full on this node, retry later', { running, waiting, max_waiting: maxWaiting });
    }
  };

  // Resolves at once: the continuation is started now if a slot is free, else queued.
  // `onAbandon` is called only when the platform stop prevents the continuation from ending.
  const schedule = async (task: ContinuationTask, logMeta: Record<string, unknown> = {}, onAbandon?: ContinuationAbandonFn) => {
    const continuation: QueuedContinuation = { task, logMeta, onAbandon };
    if (draining) {
      // The stop started between assertAccepting and here: the connector step is registered, so register the interruption.
      await reportAbandon(continuation, 'shutdown_before_start');
      return;
    }
    const key = playbookKey(logMeta);
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

  // Called when the node stops. Resolves within `timeoutMs` (plus the time to register the interruptions).
  const drain = async (timeoutMs: number) => {
    draining = true;
    const notStarted = Array.from(queues.values()).flat();
    queues.clear();
    waiting = 0;
    const pending = Array.from(inFlight);
    if (pending.length > 0) {
      logApp.info(`[OPENCTI-MODULE] Playbook manager waiting for ${pending.length} running continuation(s) before stopping`, { manager: 'PLAYBOOK_MANAGER', timeoutMs });
      let timer: NodeJS.Timeout | undefined;
      const timeout = new Promise<void>((resolve) => {
        timer = setTimeout(resolve, Math.max(0, timeoutMs));
      });
      await Promise.race([Promise.all(pending.map((entry) => entry.done)), timeout]);
      if (timer) clearTimeout(timer);
    }
    const abandoned = pending.filter((entry) => inFlight.has(entry));
    await Promise.all([
      ...notStarted.map((continuation) => reportAbandon(continuation, 'shutdown_before_start')),
      ...abandoned.map((entry) => reportAbandon(entry.continuation, 'shutdown_timeout')),
    ]);
    return { completed: pending.length - abandoned.length, abandoned: abandoned.length, notStarted: notStarted.length };
  };

  return {
    assertAccepting,
    schedule,
    drain,
    running: () => running,
    waiting: () => waiting,
    runningFor: (playbookId: string) => runningByPlaybook.get(playbookId) ?? 0,
  };
};

const PLAYBOOK_CONTINUATION_MAX_CONCURRENCY: number = conf.get('playbook_manager:callback_continuation_max_concurrency') || 10;
const PLAYBOOK_CONTINUATION_MAX_CONCURRENCY_PER_PLAYBOOK: number = conf.get('playbook_manager:callback_continuation_max_concurrency_per_playbook') || 3;
const PLAYBOOK_CONTINUATION_MAX_WAITING: number = conf.get('playbook_manager:callback_continuation_max_waiting') ?? 1000;
export const PLAYBOOK_CONTINUATION_SHUTDOWN_TIMEOUT: number = conf.get('playbook_manager:callback_continuation_shutdown_timeout') ?? 20000;

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
