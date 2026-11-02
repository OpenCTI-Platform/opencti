import conf from '../config/conf';
import { FunctionalError } from '../config/errors';
import type { WorkerRequest } from './safeEjs.worker';
import { createWorkerPool } from './workerPool';

const pool = createWorkerPool<WorkerRequest, string>({
  workerFile: 'safeEjs.worker.mjs',
  idlePoolSize: conf.get('safe_ejs:idle_pool_size') ?? 2,
  maxTasksPerWorker: conf.get('safe_ejs:max_renders_per_worker') ?? 1000,
  resourceLimits: {
    maxOldGenerationSizeMb: conf.get('safe_ejs:resource_limits:max_old_generation_size_mb') ?? 50,
    maxYoungGenerationSizeMb: conf.get('safe_ejs:resource_limits:max_young_generation_size_mb') ?? 10,
    codeRangeSizeMb: conf.get('safe_ejs:resource_limits:code_range_size_mb') ?? 10,
    stackSizeMb: conf.get('safe_ejs:resource_limits:stack_size_mb') ?? 4,
  },
  // The template comes from the user: a timeout is reported as a functional error, not a platform failure
  timeoutError: (timeout) => FunctionalError(`Rendering timeout after ${timeout}ms`, { timeout }),
});

export const renderInPool = (request: WorkerRequest, timeout: number): Promise<string> => pool.run(request, timeout);

// Exposed for tests and for a clean platform shutdown.
export const shutdownSafeEjsPool = () => pool.shutdown();
