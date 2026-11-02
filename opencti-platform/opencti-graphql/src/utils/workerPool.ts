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
  maxTasksPerWorker: number;
  resourceLimits: ResourceLimits;
  timeoutError: (timeout: number) => Error;
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

// A worker handles one task at a time: a timeout then terminates exactly the task that hung,
// and never a bystander sharing the same thread.
export const createWorkerPool = <Request, Result>(poolOptions: WorkerPoolOptions): WorkerPool<Request, Result> => {
  const { workerFile, idlePoolSize, maxTasksPerWorker, resourceLimits, timeoutError } = poolOptions;
  let shuttingDown = false;
  const idleWorkers: PooledWorker[] = [];
  const activeWorkers = new Set<PooledWorker>();

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

  const acquireWorker = (): PooledWorker => {
    if (shuttingDown) {
      throw new Error(`Worker pool ${workerFile} is shutting down`);
    }
    const available = idleWorkers.pop() ?? spawnWorker();
    activeWorkers.add(available);
    return available;
  };

  const discardWorker = (pooled: PooledWorker) => {
    retireWorker(pooled);
    void pooled.worker.terminate().catch(() => {});
  };

  // Returns the worker to the pool, or retires it once it has run enough tasks that its heap budget
  // can no longer be read as a per-task limit.
  const releaseWorker = (pooled: PooledWorker) => {
    if (pooled.retired) {
      return;
    }
    if (pooled.tasks >= maxTasksPerWorker || idleWorkers.length >= idlePoolSize) {
      discardWorker(pooled);
      return;
    }
    idleWorkers.push(pooled);
  };

  const run = async (request: Request, timeout: number): Promise<Result> => {
    const deadline = performance.now() + timeout;
    const pooled = acquireWorker();
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
    const onError = (error: Error) => {
      poisoned = true;
      settle(() => reject(new Error(`Worker error: ${error.message}`, { cause: error })));
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
      activeWorkers.delete(pooled);
      if (poisoned) {
        discardWorker(pooled);
      } else {
        releaseWorker(pooled);
      }
    }
  };

  const shutdown = async () => {
    shuttingDown = true;
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
