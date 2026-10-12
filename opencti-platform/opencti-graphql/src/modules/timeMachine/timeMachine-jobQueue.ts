import { logApp } from '../../config/conf';

export interface BoundedJobQueue {
  // False when a job with the same key is already queued or running, or when the queue is full
  enqueue: (key: string, run: () => Promise<void>) => boolean;
  // Forgets the jobs that have not started; the running ones finish
  clear: () => void;
  // Jobs queued or running
  size: () => number;
  // Resolves once no job is queued or running
  idle: () => Promise<void>;
}

/**
 * Jobs run apart from their caller, at most `concurrency` at a time. A job already queued or running under the same
 * key is not queued again, and at most `maxPending` jobs wait: the caller never waits for them. The queue lives in
 * memory, so a caller that must not lose a job keeps it until the job itself reports it done.
 */
export const createBoundedJobQueue = (name: string, concurrency: number, maxPending: number): BoundedJobQueue => {
  let pending: Array<{ key: string; run: () => Promise<void> }> = [];
  const keys = new Set<string>();
  let running = 0;
  let idleWaiters: Array<() => void> = [];
  const notifyIdle = () => {
    if (running === 0 && pending.length === 0) {
      idleWaiters.forEach((resolve) => resolve());
      idleWaiters = [];
    }
  };
  const drain = () => {
    while (running < concurrency && pending.length > 0) {
      const job = pending.shift() as { key: string; run: () => Promise<void> };
      running += 1;
      job.run()
        // The caller keeps the jobs it must not lose and runs a failed one again
        .catch((err) => logApp.warn('[OPENCTI-MODULE] Queued job failed', { cause: err, queue: name, key: job.key }))
        .finally(() => {
          running -= 1;
          keys.delete(job.key);
          drain();
          notifyIdle();
        });
    }
  };
  return {
    enqueue: (key, run) => {
      if (keys.has(key)) return false;
      if (pending.length >= maxPending) {
        logApp.debug('[OPENCTI-MODULE] Job queue full, the job is not queued', { queue: name, key, max_pending: maxPending });
        return false;
      }
      keys.add(key);
      pending.push({ key, run });
      drain();
      return true;
    },
    clear: () => {
      pending.forEach((job) => keys.delete(job.key));
      pending = [];
      notifyIdle();
    },
    size: () => pending.length + running,
    idle: () => {
      if (running === 0 && pending.length === 0) return Promise.resolve();
      return new Promise((resolve) => {
        idleWaiters.push(resolve);
      });
    },
  };
};
