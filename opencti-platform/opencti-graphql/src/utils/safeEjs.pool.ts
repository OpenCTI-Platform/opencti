import { Worker } from 'worker_threads';
import conf from '../config/conf';
import type { WorkerReply, WorkerRequest } from './safeEjs.worker';

const POOL_SIZE: number = conf.get('safe_ejs:pool_size') ?? 2;
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
}

// A worker handles one render at a time: a timeout then terminates exactly the render that hung,
// and never a bystander sharing the same thread.
const idleWorkers: PooledWorker[] = [];
const waitingForWorker: Array<(pooled: PooledWorker) => void> = [];
let livingWorkers = 0;

const resolveWorkerUrl = () => {
  const isProduction = import.meta.url.endsWith('.mjs');
  return new URL(isProduction ? 'safeEjs.worker.mjs' : '../../build/safeEjs.worker.mjs', import.meta.url);
};

const spawnWorker = (): PooledWorker => {
  const worker = new Worker(resolveWorkerUrl(), { resourceLimits: RESOURCE_LIMITS });
  // An idle worker must never hold the platform open on shutdown. A render in flight keeps the
  // event loop alive through its own timeout timer.
  worker.unref();
  livingWorkers += 1;
  return { worker, renders: 0 };
};

const acquireWorker = (): Promise<PooledWorker> => {
  const available = idleWorkers.pop();
  if (available) {
    return Promise.resolve(available);
  }
  if (livingWorkers < POOL_SIZE) {
    return Promise.resolve(spawnWorker());
  }
  return new Promise((resolve) => {
    waitingForWorker.push(resolve);
  });
};

const handOver = (pooled: PooledWorker) => {
  const waiting = waitingForWorker.shift();
  if (waiting) {
    waiting(pooled);
  } else {
    idleWorkers.push(pooled);
  }
};

const discardWorker = async (pooled: PooledWorker) => {
  livingWorkers -= 1;
  try {
    await pooled.worker.terminate();
  } catch {
    // the worker is already gone
  }
  if (waitingForWorker.length > 0 && livingWorkers < POOL_SIZE) {
    handOver(spawnWorker());
  }
};

// Returns the worker to the pool, or retires it once it has rendered enough that its heap budget
// can no longer be read as a per-render limit.
const releaseWorker = async (pooled: PooledWorker) => {
  if (pooled.renders >= MAX_RENDERS_PER_WORKER) {
    await discardWorker(pooled);
    return;
  }
  handOver(pooled);
};

export const renderInPool = async (request: WorkerRequest, timeout: number): Promise<string> => {
  const pooled = await acquireWorker();
  pooled.renders += 1;
  const { worker } = pooled;
  let settled = false;
  let timer: NodeJS.Timeout | undefined;
  // A worker that timed out, crashed or exited is never handed to another render: whatever state
  // the template left behind dies with the thread.
  let poisoned = false;
  const cleanUp = () => {
    if (timer) clearTimeout(timer);
    worker.removeAllListeners('message');
    worker.removeAllListeners('error');
    worker.removeAllListeners('exit');
  };
  try {
    return await new Promise<string>((resolve, reject) => {
      const settle = (fn: () => void) => {
        if (!settled) {
          settled = true;
          cleanUp();
          fn();
        }
      };
      worker.on('message', (message: WorkerReply) => {
        if (message.success && message.result !== undefined) {
          settle(() => resolve(message.result as string));
        } else {
          settle(() => reject(new Error(message.error || 'Unknown worker error')));
        }
      });
      worker.on('error', (error: Error) => {
        poisoned = true;
        settle(() => reject(new Error(`Worker error: ${error.message}`, { cause: error })));
      });
      worker.on('exit', (code) => {
        poisoned = true;
        settle(() => reject(new Error(`Worker stopped with exit code ${code}`)));
      });
      timer = setTimeout(() => {
        poisoned = true;
        settle(() => reject(new Error(`Rendering timeout after ${timeout}ms`)));
      }, timeout);
      worker.postMessage(request);
    });
  } finally {
    cleanUp();
    if (poisoned) {
      await discardWorker(pooled);
    } else {
      await releaseWorker(pooled);
    }
  }
};

// Exposed for tests and for a clean platform shutdown.
export const shutdownSafeEjsPool = async () => {
  const pooled = idleWorkers.splice(0, idleWorkers.length);
  livingWorkers -= pooled.length;
  await Promise.all(pooled.map(async ({ worker }) => {
    try {
      await worker.terminate();
    } catch {
      // already gone
    }
  }));
};
