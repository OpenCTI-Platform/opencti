import { afterEach, describe, expect, it, vi } from 'vitest';
import { Worker } from 'worker_threads';
import { FunctionalError } from '../../../src/config/errors';
import type { JsonPathQuery } from '../../../src/utils/jsonPath.worker';
import { createWorkerPool, type WorkerPoolOptions } from '../../../src/utils/workerPool';

const poolOptions: WorkerPoolOptions = {
  workerFile: 'jsonPath.worker.mjs',
  idlePoolSize: 2,
  maxTasksPerWorker: 100,
  resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 16, codeRangeSizeMb: 10, stackSizeMb: 4 },
  timeoutError: (timeout) => FunctionalError(`timeout after ${timeout}ms`),
};

const query = (i: number): JsonPathQuery => ({ path: '$.items[?(@.type == \'domain\')].value', json: { items: [{ type: 'domain', value: `${i}` }] }, wrap: false });

describe('check createWorkerPool', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('runs concurrent tasks on at most maxPoolSize workers', async () => {
    const pool = createWorkerPool<JsonPathQuery, any>({ ...poolOptions, maxPoolSize: 2 });
    const postMessageSpy = vi.spyOn(Worker.prototype, 'postMessage');
    try {
      const results = await Promise.all(Array.from({ length: 8 }, (_, i) => pool.run(query(i), 5000)));
      expect(results).toEqual(Array.from({ length: 8 }, (_, i) => [`${i}`]));
      const threads = new Set(postMessageSpy.mock.contexts.map((worker) => (worker as Worker).threadId));
      expect(threads.size).toBe(2);
    } finally {
      await pool.shutdown();
    }
  });

  it('starts the timeout of a waiting task once it gets a worker', async () => {
    const pool = createWorkerPool<JsonPathQuery, any>({ ...poolOptions, maxPoolSize: 1 });
    try {
      const json = { items: Array.from({ length: 100000 }, (_, i) => ({ type: 'domain', value: `${i}` })) };
      // The first task holds the only worker until it times out, the second one waits longer than its own timeout
      const first = pool.run({ path: '$.items[?(@.type == \'domain\')].value', json }, 1);
      const second = pool.run(query(1), 300);
      await expect(first).rejects.toThrow('timeout after 1ms');
      expect(await second).toEqual(['1']);
    } finally {
      await pool.shutdown();
    }
  });

  it('reports a worker out of memory with the configured error', async () => {
    const pool = createWorkerPool<JsonPathQuery, any>({
      ...poolOptions,
      resourceLimits: { ...poolOptions.resourceLimits, maxOldGenerationSizeMb: 8, maxYoungGenerationSizeMb: 4 },
      outOfMemoryError: () => FunctionalError('out of memory'),
    });
    try {
      const json = { items: Array.from({ length: 300000 }, (_, i) => ({ type: 'domain', value: `value-${i}` })) };
      await expect(pool.run({ path: '$.items[?(@.type == \'domain\')].value', json }, 30000)).rejects.toMatchObject({
        message: 'out of memory',
        extensions: { code: 'FUNCTIONAL_ERROR' },
      });
      // The worker that ran out of memory is replaced
      expect(await pool.run(query(2), 5000)).toEqual(['2']);
    } finally {
      await pool.shutdown();
    }
  });

  it('rejects waiting tasks on shutdown', async () => {
    const pool = createWorkerPool<JsonPathQuery, any>({ ...poolOptions, maxPoolSize: 1 });
    const settled = (promise: Promise<unknown>) => promise.then(() => 'resolved').catch((error) => error.message);
    const json = { items: Array.from({ length: 100000 }, (_, i) => ({ type: 'domain', value: `${i}` })) };
    const running = settled(pool.run({ path: '$.items[?(@.type == \'domain\')].value', json }, 30000));
    const waiting = settled(pool.run(query(3), 30000));
    await pool.shutdown();
    expect(await waiting).toBe('Worker pool jsonPath.worker.mjs is shutting down');
    expect(await running).not.toBe('resolved');
  });
});
