import conf, { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';

export type ContinuationAbandonReason = 'shutdown_timeout' | 'shutdown_before_start';

export type ContinuationOptions = {
  logMeta?: Record<string, unknown>;
  // Called when the node stops before the continuation could end, so the caller can leave
  // a trace of it (an error observation on the playbook execution). Never called otherwise.
  onAbandon?: (reason: ContinuationAbandonReason) => Promise<void>;
};

type Waiter = {
  resolve: () => void;
  reject: (error: Error) => void;
};

type InFlight = {
  done: Promise<void>;
  onAbandon?: ContinuationOptions['onAbandon'];
  logMeta: Record<string, unknown>;
};

/**
 * Bounded scheduler for the playbook steps that follow an external callback.
 *
 * When a connector step calls back (`playbookStepExecution`), the rest of the chain
 * (AI transforms, ingestion, notifications...) is run in the background so the
 * connector is acknowledged as soon as its bundle is accepted.
 * To keep backpressure, at most `maxConcurrency` continuations run at once on this node:
 * `schedule` resolves when the continuation has STARTED (a slot was free), not when it has
 * finished. When every slot is taken, the caller waits for a free slot, so a flood of
 * callbacks can neither start unbounded concurrent downstream calls nor pile up unbounded
 * work in memory.
 *
 * The continuations live in the memory of this node. `drain` is called when the node stops:
 * it refuses new continuations, refuses the callers still waiting for a slot (their connector
 * sees an error and can retry), waits a bounded time for the running ones, and reports every
 * continuation that could not end through its `onAbandon`, so a stop never loses a chain silently.
 */
export const createContinuationScheduler = (maxConcurrency: number) => {
  const limit = Math.max(1, Math.floor(maxConcurrency));
  let running = 0;
  let draining = false;
  const waiters: Array<Waiter> = [];
  const inFlight = new Set<InFlight>();

  const acquire = async () => {
    if (running < limit) {
      running += 1;
      return;
    }
    // The slot is handed over by release(): running is not decremented then incremented.
    await new Promise<void>((resolve, reject) => {
      waiters.push({ resolve, reject });
    });
  };

  const release = () => {
    const next = waiters.shift();
    if (next) {
      next.resolve();
    } else {
      running -= 1;
    }
  };

  const reportAbandon = async (onAbandon: ContinuationOptions['onAbandon'], reason: ContinuationAbandonReason, logMeta: Record<string, unknown>) => {
    logApp.error('[OPENCTI-MODULE] Playbook manager continuation interrupted by the platform stop', { manager: 'PLAYBOOK_MANAGER', reason, ...logMeta });
    if (onAbandon) {
      try {
        await onAbandon(reason);
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Playbook manager cannot register an interrupted continuation', { cause: error, manager: 'PLAYBOOK_MANAGER', reason, ...logMeta });
      }
    }
  };

  const schedule = async (task: () => Promise<void>, options: ContinuationOptions = {}) => {
    const logMeta = options.logMeta ?? {};
    if (draining) {
      await reportAbandon(options.onAbandon, 'shutdown_before_start', logMeta);
      throw FunctionalError('Playbook continuation refused, the platform is stopping', logMeta);
    }
    try {
      await acquire();
    } catch (error) {
      await reportAbandon(options.onAbandon, 'shutdown_before_start', logMeta);
      throw error;
    }
    // Detached on purpose: the caller only waits for the slot, never for the task.
    const entry: InFlight = { done: Promise.resolve(), onAbandon: options.onAbandon, logMeta };
    entry.done = (async () => {
      try {
        await task();
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Playbook manager continuation error', { cause: error, manager: 'PLAYBOOK_MANAGER', ...logMeta });
      } finally {
        inFlight.delete(entry);
        release();
      }
    })();
    inFlight.add(entry);
  };

  const drain = async (timeoutMs: number) => {
    draining = true;
    // Callers still waiting for a slot have not been answered yet: refuse them, their connector sees the error.
    const refused = waiters.splice(0);
    refused.forEach((waiter) => waiter.reject(FunctionalError('Playbook continuation refused, the platform is stopping')));
    if (inFlight.size === 0) {
      return { completed: 0, abandoned: 0, refused: refused.length };
    }
    const pending = Array.from(inFlight);
    logApp.info(`[OPENCTI-MODULE] Playbook manager waiting for ${pending.length} running continuation(s) before stopping`, { manager: 'PLAYBOOK_MANAGER', timeoutMs });
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, Math.max(0, timeoutMs));
    });
    await Promise.race([Promise.all(pending.map((entry) => entry.done)), timeout]);
    if (timer) clearTimeout(timer);
    const abandoned = pending.filter((entry) => inFlight.has(entry));
    await Promise.all(abandoned.map((entry) => reportAbandon(entry.onAbandon, 'shutdown_timeout', entry.logMeta)));
    return { completed: pending.length - abandoned.length, abandoned: abandoned.length, refused: refused.length };
  };

  return {
    schedule,
    drain,
    running: () => running,
    waiting: () => waiters.length,
  };
};

const PLAYBOOK_CONTINUATION_MAX_CONCURRENCY: number = conf.get('playbook_manager:callback_continuation_max_concurrency') || 10;
export const PLAYBOOK_CONTINUATION_SHUTDOWN_TIMEOUT: number = conf.get('playbook_manager:callback_continuation_shutdown_timeout') ?? 20000;

export const playbookContinuationScheduler = createContinuationScheduler(PLAYBOOK_CONTINUATION_MAX_CONCURRENCY);
