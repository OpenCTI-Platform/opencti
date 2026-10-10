import { Worker } from 'worker_threads';
import conf from '../config/conf';
import type { WorkerReply, WorkerRequest } from './safeEjs.worker';

const CORE_POOL_SIZE: number = conf.get('safe_ejs:pool_size') ?? 2;
const MAX_RENDERS_PER_WORKER: number = conf.get('safe_ejs:max_renders_per_worker') ?? 1000;
const RESOURCE_LIMITS = {
  maxOldGenerationSizeMb: conf.get('safe_ejs:resource_limits:max_old_generation_size_mb') ?? 50,
  maxYoungGenerationSizeMb: conf.get('safe_ejs:resource_limits:max_young_generation_size_mb') ?? 10,
  codeRangeSizeMb: conf.get('safe_ejs:resource_limits:code_range_size_mb') ?? 10,
  stackSizeMb: conf.get('safe_ejs:resource_limits:stack_size_mb') ?? 4,
};

interface PooledWorker {
  worker: Worker;
  renders: number;
  retired: boolean;
}

// A worker handles one render at a time: a timeout then terminates exactly the render that hung,
// and never a bystander sharing the same thread.
let shuttingDown = false;
const idleWorkers: PooledWorker[] = [];
const activeWorkers = new Set<PooledWorker>();

const resolveWorkerUrl = () => {
  const isProduction = import.meta.url.endsWith('.mjs');
  return new URL(isProduction ? 'safeEjs.worker.mjs' : '../../build/safeEjs.worker.mjs', import.meta.url);
};

const spawnWorker = (): PooledWorker => {
  const worker = new Worker(resolveWorkerUrl(), { resourceLimits: RESOURCE_LIMITS });
  // An idle worker must never hold the platform open on shutdown. A render in flight keeps the
  // event loop alive through its own timeout timer.
  worker.unref();
  const pooled: PooledWorker = { worker, renders: 0, retired: false };
  worker.on('error', () => retireWorker(pooled));
  worker.on('exit', () => retireWorker(pooled));
  return pooled;
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

const timeoutError = (timeout: number) => new Error(`Rendering timeout after ${timeout}ms`);

const acquireWorker = (): PooledWorker => {
  if (shuttingDown) {
    throw new Error('safeEjs worker pool is shutting down');
  }
  const available = idleWorkers.pop() ?? spawnWorker();
  activeWorkers.add(available);
  return available;
};

const discardWorker = (pooled: PooledWorker) => {
  retireWorker(pooled);
  void pooled.worker.terminate().catch(() => {});
};

// Returns the worker to the pool, or retires it once it has rendered enough that its heap budget
// can no longer be read as a per-render limit.
const releaseWorker = (pooled: PooledWorker) => {
  if (pooled.retired) {
    return;
  }
  if (pooled.renders >= MAX_RENDERS_PER_WORKER || idleWorkers.length >= CORE_POOL_SIZE) {
    discardWorker(pooled);
    return;
  }
  idleWorkers.push(pooled);
};

export const renderInPool = async (request: WorkerRequest, timeout: number): Promise<string> => {
  const deadline = performance.now() + timeout;
  const pooled = acquireWorker();
  pooled.renders += 1;
  const { worker } = pooled;
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  // A worker that timed out, crashed or exited is never handed to another render: whatever state
  // the template left behind dies with the thread.
  let poisoned = false;
  const onMessage = (message: WorkerReply) => {
    if (message.success && message.result !== undefined) {
      settle(() => resolve(message.result as string));
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
  let resolve!: (value: string) => void;
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
    return await new Promise<string>((res, rej) => {
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

// Exposed for tests and for a clean platform shutdown.
export const shutdownSafeEjsPool = async () => {
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
