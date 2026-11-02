import { JSONPath } from 'jsonpath-plus';
import conf from '../config/conf';
import { FunctionalError } from '../config/errors';
import type { JsonPathQuery } from './jsonPath.worker';
import { createWorkerPool } from './workerPool';

const TIMEOUT: number = conf.get('json_path:timeout') ?? 5000;

const pool = createWorkerPool<JsonPathQuery, any>({
  workerFile: 'jsonPath.worker.mjs',
  idlePoolSize: conf.get('json_path:idle_pool_size') ?? 2,
  maxTasksPerWorker: conf.get('json_path:max_queries_per_worker') ?? 10000,
  resourceLimits: {
    maxOldGenerationSizeMb: conf.get('json_path:resource_limits:max_old_generation_size_mb') ?? 512,
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
  return pool.run(query, TIMEOUT);
};

// Exposed for tests and for a clean platform shutdown.
export const shutdownJsonPathPool = () => pool.shutdown();
