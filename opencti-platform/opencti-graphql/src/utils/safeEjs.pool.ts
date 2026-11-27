import conf from '../config/conf';
import type { WorkerRequest } from './safeEjs.worker';
import { createWorkerPool, type HostCallFunction } from './workerPool';

// Main-thread functions a template helper may call from a render worker, registered by their owner
const hostCalls: Record<string, HostCallFunction> = Object.create(null);
export const registerSafeEjsHostCall = (name: string, fn: HostCallFunction) => {
  hostCalls[name] = fn;
};

const pool = createWorkerPool<WorkerRequest, string>({
  hostCalls,
  workerFile: 'safeEjs.worker.mjs',
  idlePoolSize: conf.get('safe_ejs:idle_pool_size') ?? 2,
  maxTasksPerWorker: conf.get('safe_ejs:max_renders_per_worker') ?? 1000,
  resourceLimits: {
    maxOldGenerationSizeMb: conf.get('safe_ejs:resource_limits:max_old_generation_size_mb') ?? 50,
    maxYoungGenerationSizeMb: conf.get('safe_ejs:resource_limits:max_young_generation_size_mb') ?? 10,
    codeRangeSizeMb: conf.get('safe_ejs:resource_limits:code_range_size_mb') ?? 10,
    stackSizeMb: conf.get('safe_ejs:resource_limits:stack_size_mb') ?? 4,
  },
  timeoutError: (timeout) => new Error(`Rendering timeout after ${timeout}ms`),
});

export const renderInPool = (request: WorkerRequest, timeout: number): Promise<string> => pool.run(request, timeout);

// Exposed for tests and for a clean platform shutdown.
export const shutdownSafeEjsPool = () => pool.shutdown();
