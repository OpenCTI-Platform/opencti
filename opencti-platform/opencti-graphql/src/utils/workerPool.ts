import { MessageChannel, receiveMessageOnPort, Worker, type MessagePort, type ResourceLimits, type WorkerOptions } from 'worker_threads';

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
  // An idle worker still holds the memory of its last task: it is terminated after this delay, in ms. Kept if not set.
  idleTimeout?: number;
  resourceLimits: ResourceLimits;
  timeoutError: (timeout: number) => Error;
  // Functions a worker may call synchronously on the main thread (see hostCall in the worker)
  hostCalls?: Record<string, HostCallFunction>;
}

// The arguments cross as JSON, the result as a string
export type HostCallFunction = (...args: unknown[]) => string;
interface HostCallRequest { id: number; name: string; args: string }
type HostCallReply = { id: number; ok: true; value: string } | { id: number; ok: false; error: string };
export interface HostChannel { port: MessagePort; signal: Int32Array }

export interface WorkerPool<Request, Result> {
  run: (request: Request, timeout: number) => Promise<Result>;
  shutdown: () => Promise<void>;
}

interface PooledWorker {
  worker: Worker;
  tasks: number;
  retired: boolean;
  idleTimer?: NodeJS.Timeout;
}

interface WaitingTask {
  resolve: (pooled: PooledWorker) => void;
  reject: (reason: Error) => void;
}

// Replies carry the call id and the signal is a counter, so a late reply is never read as the next answer
const attachHostCalls = (options: WorkerOptions, hostCalls: Record<string, HostCallFunction>) => {
  const channel = new MessageChannel();
  const signal = new Int32Array(new SharedArrayBuffer(4));
  options.workerData = { hostChannel: { port: channel.port2, signal } satisfies HostChannel };
  options.transferList = [channel.port2];
  channel.port1.on('message', (request: HostCallRequest) => {
    let reply: HostCallReply;
    try {
      const fn = Object.hasOwn(hostCalls, request.name) ? hostCalls[request.name] : undefined;
      if (!fn) {
        throw new Error(`Unknown host call ${JSON.stringify(request.name)}`);
      }
      reply = { id: request.id, ok: true, value: String(fn(...JSON.parse(request.args))) };
    } catch (error) {
      reply = { id: request.id, ok: false, error: error instanceof Error ? error.message : 'Host call failed' };
    }
    channel.port1.postMessage(reply);
    Atomics.add(signal, 0, 1);
    Atomics.notify(signal, 0);
  });
  channel.port1.unref();
  return channel;
};

// Worker side: calls a main-thread function synchronously, blocking until its own reply arrives
export const createHostCall = ({ port, signal }: HostChannel, timeout: number) => {
  let lastId = 0;
  // Replies left by an abandoned call are dropped here
  const takeReply = (id: number): HostCallReply | undefined => {
    let received = receiveMessageOnPort(port);
    while (received) {
      const reply = received.message as HostCallReply;
      if (reply.id === id) {
        return reply;
      }
      received = receiveMessageOnPort(port);
    }
    return undefined;
  };
  return (name: string, args: unknown[]): string => {
    lastId += 1;
    const id = lastId;
    const deadline = performance.now() + timeout;
    port.postMessage({ id, name, args: JSON.stringify(args) } satisfies HostCallRequest);
    let seen = Atomics.load(signal, 0);
    let reply = takeReply(id);
    while (!reply) {
      const remaining = deadline - performance.now();
      if (remaining <= 0 || Atomics.wait(signal, 0, seen, remaining) === 'timed-out') {
        throw new Error(`Host call ${name} timed out`);
      }
      seen = Atomics.load(signal, 0);
      reply = takeReply(id);
    }
    if (!reply.ok) {
      throw new Error(reply.error);
    }
    return reply.value;
  };
};

// A worker handles one task at a time: a timeout then terminates exactly the task that hung,
// and never a bystander sharing the same thread.
export const createWorkerPool = <Request, Result>(poolOptions: WorkerPoolOptions): WorkerPool<Request, Result> => {
  const { workerFile, idlePoolSize, maxPoolSize = Infinity, maxTasksPerWorker, idleTimeout, resourceLimits, timeoutError, hostCalls } = poolOptions;
  let shuttingDown = false;
  const idleWorkers: PooledWorker[] = [];
  const activeWorkers = new Set<PooledWorker>();
  const waitingTasks: WaitingTask[] = [];

  const resolveWorkerUrl = () => {
    const isProduction = import.meta.url.endsWith('.mjs');
    return new URL(isProduction ? workerFile : `../../build/${workerFile}`, import.meta.url);
  };

  const stopIdleTimer = (pooled: PooledWorker) => {
    if (pooled.idleTimer) {
      clearTimeout(pooled.idleTimer);
      pooled.idleTimer = undefined;
    }
  };

  const retireWorker = (pooled: PooledWorker) => {
    if (pooled.retired) {
      return;
    }
    pooled.retired = true;
    stopIdleTimer(pooled);
    const index = idleWorkers.indexOf(pooled);
    if (index !== -1) {
      idleWorkers.splice(index, 1);
    }
  };

  const spawnWorker = (): PooledWorker => {
    const options: WorkerOptions = Object.assign(Object.create(null), { resourceLimits });
    const channel = hostCalls ? attachHostCalls(options, hostCalls) : undefined;
    const worker = new Worker(resolveWorkerUrl(), options);
    worker.on('exit', () => channel?.port1.close());
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
    if (idle) {
      stopIdleTimer(idle);
    }
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
      if (idleTimeout !== undefined) {
        pooled.idleTimer = setTimeout(() => discardWorker(pooled), idleTimeout);
        pooled.idleTimer.unref();
      }
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
