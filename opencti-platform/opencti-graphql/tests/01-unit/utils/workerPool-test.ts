import { afterEach, describe, expect, it, vi } from 'vitest';
import { MessageChannel, Worker } from 'worker_threads';
import { FunctionalError } from '../../../src/config/errors';
import type { JsonPathQuery } from '../../../src/utils/jsonPath.worker';
import type { WorkerRequest } from '../../../src/utils/safeEjs.worker';
import { createHostCall, createWorkerPool, type WorkerPoolOptions } from '../../../src/utils/workerPool';

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

  it('terminates a worker that stays idle longer than idleTimeout', async () => {
    const pool = createWorkerPool<JsonPathQuery, any>({ ...poolOptions, idleTimeout: 200 });
    const postMessageSpy = vi.spyOn(Worker.prototype, 'postMessage');
    const terminateSpy = vi.spyOn(Worker.prototype, 'terminate');
    const threadOf = (call: number) => (postMessageSpy.mock.contexts[call] as Worker).threadId;
    try {
      await pool.run(query(1), 5000);
      // Reused while the next task comes before the idle timeout
      await pool.run(query(2), 5000);
      expect(threadOf(1)).toBe(threadOf(0));
      expect(terminateSpy).not.toHaveBeenCalled();
      // Terminated once idle for longer, and replaced by a new worker
      await vi.waitFor(() => expect(terminateSpy).toHaveBeenCalledTimes(1), { timeout: 2000 });
      expect(await pool.run(query(3), 5000)).toEqual(['3']);
      expect(threadOf(2)).not.toBe(threadOf(0));
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

// Stands in for the main thread: answers each host call after the delay given for it
const RESPONDER = `
const { workerData } = require('worker_threads');
const { port, signal, delays } = workerData;
let count = 0;
port.on('message', (request) => {
  const delay = delays[count] ?? 0;
  count += 1;
  setTimeout(() => {
    const reply = request.name === 'fail'
      ? { id: request.id, ok: false, error: 'failed' }
      : { id: request.id, ok: true, value: request.name + ':' + request.args };
    port.postMessage(reply);
    Atomics.add(signal, 0, 1);
    Atomics.notify(signal, 0);
  }, delay);
});
`;

const startResponder = (delays: number[], timeout: number) => {
  const { port1, port2 } = new MessageChannel();
  const signal = new Int32Array(new SharedArrayBuffer(4));
  const responder = new Worker(RESPONDER, { eval: true, workerData: { port: port1, signal, delays }, transferList: [port1] });
  const stop = () => {
    port2.close();
    return responder.terminate();
  };
  return { hostCall: createHostCall({ port: port2, signal }, timeout), stop };
};

describe('check host calls through the pool', () => {
  it('answers an unknown host call with an error', async () => {
    const pool = createWorkerPool<WorkerRequest, string>({ ...poolOptions, workerFile: 'safeEjs.worker.mjs', hostCalls: Object.create(null) });
    try {
      const request: WorkerRequest = { template: '<?- patternFromValue("IPv4-Addr", "1.1.1.1") ?>', data: {}, options: { delimiter: '?' }, useJsonMapperHelpers: true };
      await expect(pool.run(request, 5000)).rejects.toThrow('Unknown host call "patternFromValue"');
    } finally {
      await pool.shutdown();
    }
  });
});

describe('check createHostCall', () => {
  it('returns the reply and sends the arguments as JSON', async () => {
    const { hostCall, stop } = startResponder([], 5000);
    try {
      expect(hostCall('echo', [1, 'a', null, ['x']])).toEqual('echo:[1,"a",null,["x"]]');
      expect(() => hostCall('fail', [])).toThrow('failed');
    } finally {
      await stop();
    }
  });

  it('drops a late reply waiting before the next call', async () => {
    const { hostCall, stop } = startResponder([300, 0], 100);
    try {
      expect(() => hostCall('first', [])).toThrow(/timed out/);
      await new Promise((resolve) => {
        setTimeout(resolve, 400);
      });
      expect(hostCall('second', [])).toEqual('second:[]');
    } finally {
      await stop();
    }
  });

  it('drops a late reply arriving while the next call waits', async () => {
    // first reply at ~1300 ms, after its timeout; second call sent at ~1000 ms, replied at ~1600 ms
    const { hostCall, stop } = startResponder([1300, 600], 1000);
    try {
      expect(() => hostCall('first', [])).toThrow(/timed out/);
      expect(hostCall('second', [])).toEqual('second:[]');
    } finally {
      await stop();
    }
  });
});
