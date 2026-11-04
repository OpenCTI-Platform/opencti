import { JSONPath } from 'jsonpath-plus';
import conf from '../config/conf';
import { FunctionalError } from '../config/errors';
import type { JsonPathQuery } from './jsonPath.worker';
import { createWorkerPool } from './workerPool';

const pool = createWorkerPool<JsonPathQuery, any>({
  workerFile: 'jsonPath.worker.mjs',
  idlePoolSize: conf.get('json_path:idle_pool_size') ?? 2,
  // Each worker holds a copy of the document it filters: the bound keeps the number of copies under control
  maxPoolSize: conf.get('json_path:max_pool_size') ?? 4,
  maxTasksPerWorker: conf.get('json_path:max_queries_per_worker') ?? 10000,
  // A worker that copied a large document keeps that memory while idle: it is given back after a quiet period
  idleTimeout: conf.get('json_path:idle_timeout') ?? 60000,
  // The worker heap is not capped: a document that fits in the main thread must also fit in its copy.
  // A per-worker cap would be ignored anyway when the process runs with --max-old-space-size (NODE_OPTIONS in the images).
  resourceLimits: {
    maxYoungGenerationSizeMb: conf.get('json_path:resource_limits:max_young_generation_size_mb') ?? 32,
    codeRangeSizeMb: conf.get('json_path:resource_limits:code_range_size_mb') ?? 10,
    stackSizeMb: conf.get('json_path:resource_limits:stack_size_mb') ?? 4,
  },
  // The path comes from the user's mapper or feed: a timeout is reported as a functional error, not a platform failure
  timeoutError: (timeout) => FunctionalError(`JSONPath evaluation timeout after ${timeout}ms`, { timeout }),
});

// jsonpath-plus evaluates `?(...)` filters and `(...)` selectors as code: they run in the worker pool, with a timeout.
// A path with no parenthesis has no script: it stays in process with evaluation disabled.
const hasScriptExpression = (path: string) => path.includes('(');

export const queryJsonPath = async (query: JsonPathQuery): Promise<any> => {
  if (!hasScriptExpression(query.path)) {
    return JSONPath({ ...query, eval: false });
  }
  // The worker keeps the event loop free: the timeout only has to free a runaway worker, and leaves time to copy a large document
  const timeout: number = conf.get('json_path:timeout') ?? 60000;
  return pool.run(query, timeout);
};

// Exposed for tests and for a clean platform shutdown.
export const shutdownJsonPathPool = () => pool.shutdown();
