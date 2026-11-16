import conf, { logApp } from '../../config/conf';

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
 */
export const createContinuationScheduler = (maxConcurrency: number) => {
  const limit = Math.max(1, Math.floor(maxConcurrency));
  let running = 0;
  const waiters: Array<() => void> = [];

  const acquire = async () => {
    if (running < limit) {
      running += 1;
      return;
    }
    // The slot is handed over by release(): running is not decremented then incremented.
    await new Promise<void>((resolve) => {
      waiters.push(resolve);
    });
  };

  const release = () => {
    const next = waiters.shift();
    if (next) {
      next();
    } else {
      running -= 1;
    }
  };

  const schedule = async (task: () => Promise<void>, logMeta: Record<string, unknown> = {}) => {
    await acquire();
    // Detached on purpose: the caller only waits for the slot, never for the task.
    void (async () => {
      try {
        await task();
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Playbook manager continuation error', { cause: error, manager: 'PLAYBOOK_MANAGER', ...logMeta });
      } finally {
        release();
      }
    })();
  };

  return {
    schedule,
    running: () => running,
    waiting: () => waiters.length,
  };
};

const PLAYBOOK_CONTINUATION_MAX_CONCURRENCY: number = conf.get('playbook_manager:callback_continuation_max_concurrency') || 10;

export const playbookContinuationScheduler = createContinuationScheduler(PLAYBOOK_CONTINUATION_MAX_CONCURRENCY);
