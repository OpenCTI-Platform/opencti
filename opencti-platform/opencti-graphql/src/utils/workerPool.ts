import { Worker, type ResourceLimits, type WorkerOptions } from 'worker_threads';

export interface WorkerReply<Result> {
  success: boolean;
  result?: Result;
  error?: string;
}

export interface WorkerPoolOptions {
  // Bundled file name of the worker, resolved next to the build output
  workerFile: string;
  idlePoolSize: number;
  // Maximum number of workers running at once: tasks beyond it wait for a free worker. Unbounded if not set.
  maxPoolSize?: number;
  maxTasksPerWorker: number;
  resourceLimits: ResourceLimits;
  timeoutError: (timeout: number) => Error;
  // Error reported when a task exceeds the worker resource limits. A generic worker error if not set.
  outOfMemoryError?: () => Error;
}

export interface WorkerPool<Request, Result> {
  run: (request: Request, timeout: number) => Promise<Result>;
  shutdown: () => Promise<void>;
}

interface PooledWorker {
  worker: Worker;
  tasks: number;
  retired: boolean;
}

interface WaitingTask {
  resolve: (pooled: PooledWorker) => void;
  reject: (reason: Error) => void;
}

// A worker handles one task at a time: a timeout then terminates exactly the task that hung,
// and never a bystander sharing the same thread.
export const createWorkerPool = <Request, Result>(poolOptions: WorkerPoolOptions): WorkerPool<Request, Result> => {
  const { workerFile, idlePoolSize, maxPoolSize = Infinity, maxTasksPerWorker, resourceLimits, timeoutError, outOfMemoryError } = poolOptions;
  let shuttingDown = false;
  const idleWorkers: PooledWorker[] = [];
  const activeWorkers = new Set<PooledWorker>();
  const waitingTasks: WaitingTask[] = [];

  const resolveWorkerUrl = () => {
    const isProduction = import.meta.url.endsWith('.mjs');
    return new URL(isProduction ? workerFile : `../../build/${workerFile}`, import.meta.url);
  };

  const retireWorker = (pooled: PooledWorker) => {
    if (pooled.retired) {
      return;
    }
    pooled.retired = true;
    const index = idleWorkers.indexOf(pooled);
    if (index !== -1) {
      idleWorkers.splice(index, 1);
    }
  };

  const spawnWorker = (): PooledWorker => {
    const options: WorkerOptions = Object.assign(Object.create(null), { resourceLimits });
    const worker = new Worker(resolveWorkerUrl(), options);
    // An idle worker must never hold the platform open on shutdown. A task in flight keeps the
    // event loop alive through its own timeout timer.
    worker.unref();
    const pooled: PooledWorker = { worker, tasks: 0, retired: false };
    worker.on('error', () => retireWorker(pooled));
    worker.on('exit', () => retireWorker(pooled));
    return pooled;
  };

  const acquireWorker = (): Promise<PooledWorker> => {
    if (shuttingDown) {
      return Promise.reject(new Error(`Worker pool ${workerFile} is shutting down`));
    }
    const idle = idleWorkers.pop();
    if (idle || activeWorkers.size < maxPoolSize) {
      const available = idle ?? spawnWorker();
      activeWorkers.add(available);
      return Promise.resolve(available);
    }
    // Every worker is busy: the task waits for the first one to be released, in arrival order
    return new Promise((resolve, reject) => {
      waitingTasks.push({ resolve, reject });
    });
  };

  const discardWorker = (pooled: PooledWorker) => {
    retireWorker(pooled);
    void pooled.worker.terminate().catch(() => {});
  };

  // Hands the worker to the oldest waiting task, or returns it to the pool. A worker that cannot be reused
  // is discarded, or retired once it has run enough tasks that its heap budget can no longer be read as a
  // per-task limit; a waiting task then gets a fresh worker in its place.
  const releaseWorker = (pooled: PooledWorker, reusable: boolean) => {
    activeWorkers.delete(pooled);
    const canReuse = reusable && !pooled.retired && pooled.tasks < maxTasksPerWorker;
    if (!canReuse) {
      discardWorker(pooled);
    }
    const waiting = waitingTasks.shift();
    if (waiting) {
      try {
        const next = canReuse ? pooled : spawnWorker();
        activeWorkers.add(next);
        waiting.resolve(next);
      } catch (error) {
        waiting.reject(error as Error);
      }
      return;
    }
    if (canReuse && idleWorkers.length < idlePoolSize) {
      idleWorkers.push(pooled);
    } else if (canReuse) {
      discardWorker(pooled);
    }
  };

  const run = async (request: Request, timeout: number): Promise<Result> => {
    const pooled = await acquireWorker();
    // The budget starts once the task has a worker: time spent waiting for one is not counted
    const deadline = performance.now() + timeout;
    pooled.tasks += 1;
    const { worker } = pooled;
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    // A worker that timed out, crashed or exited is never handed to another task: whatever state
    // the task left behind dies with the thread.
    let poisoned = false;
    const onMessage = (message: WorkerReply<Result>) => {
      if (message.success) {
        settle(() => resolve(message.result as Result));
      } else {
        settle(() => reject(new Error(message.error || 'Unknown worker error')));
      }
    };
    const onError = (error: Error & { code?: string }) => {
      poisoned = true;
      if (outOfMemoryError && error.code === 'ERR_WORKER_OUT_OF_MEMORY') {
        settle(() => reject(outOfMemoryError()));
      } else {
        settle(() => reject(new Error(`Worker error: ${error.message}`, { cause: error })));
      }
    };
    const onExit = (code: number) => {
      poisoned = true;
      settle(() => reject(new Error(`Worker stopped with exit code ${code}`)));
    };
    let resolve!: (value: Result) => void;
    let reject!: (reason?: unknown) => void;
    const settle = (fn: () => void) => {
      if (!settled) {
        settled = true;
        cleanUp();
        fn();
      }
    };
    const cleanUp = () => {
      if (timer) clearTimeout(timer);
      worker.removeListener('message', onMessage);
      worker.removeListener('error', onError);
      worker.removeListener('exit', onExit);
    };
    try {
      return await new Promise<Result>((res, rej) => {
        resolve = res;
        reject = rej;
        worker.on('message', onMessage);
        worker.on('error', onError);
        worker.on('exit', onExit);
        timer = setTimeout(() => {
          poisoned = true;
          settle(() => reject(timeoutError(timeout)));
        }, Math.max(0, deadline - performance.now()));
        worker.postMessage(request);
      });
    } finally {
      cleanUp();
      releaseWorker(pooled, !poisoned);
    }
  };

  const shutdown = async () => {
    shuttingDown = true;
    waitingTasks.splice(0, waitingTasks.length).forEach((waiting) => waiting.reject(new Error(`Worker pool ${workerFile} is shutting down`)));
    const pooled = [...idleWorkers.splice(0, idleWorkers.length), ...activeWorkers];
    await Promise.all(pooled.map(async (worker) => {
      retireWorker(worker);
      try {
        await worker.worker.terminate();
      } catch {
        // already gone
      }
    }));
    shuttingDown = false;
  };

  return { run, shutdown };
};
