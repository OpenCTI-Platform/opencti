import { Worker } from 'worker_threads';
import type { Data } from 'ejs';
import type { SafeRenderOptions } from './safeEjs';
import type { WorkerReply } from './safeEjs.worker';

export type WorkerOptions = {
  timeout?: number;
  useJsonEscape?: boolean;
  resourceLimits?: {
    maxOldGenerationSizeMb?: number;
    maxYoungGenerationSizeMb: number;
    codeRangeSizeMb: number;
    stackSizeMb: number;
  };
};

export const safeRender = async (template: string, data: Data, options?: SafeRenderOptions & WorkerOptions): Promise<string> => {
  // Handle empty template directly without worker
  if (!template) {
    return '';
  }

  const timeout = options?.timeout ?? 5000; // Default 5 seconds

  // Determine the correct worker path based on the environment
  const isProduction = import.meta.url.endsWith('.mjs');
  const workerUrl = new URL(isProduction ? 'safeEjs.worker.mjs' : '../../build/safeEjs.worker.mjs', import.meta.url);

  // Handle escape function - remove it from options if it exists (can't be serialized)
  const workerOptions = { ...options };
  if (workerOptions.escape) {
    delete workerOptions.escape;
  }

  const worker = new Worker(workerUrl, {
    workerData: { template, data, options: workerOptions, useJsonEscape: options?.useJsonEscape },
    resourceLimits: {
      maxOldGenerationSizeMb: options?.resourceLimits?.maxOldGenerationSizeMb ?? 50, // 50 MB heap
      maxYoungGenerationSizeMb: options?.resourceLimits?.maxYoungGenerationSizeMb ?? 10, // 10 MB new space
      codeRangeSizeMb: options?.resourceLimits?.codeRangeSizeMb ?? 10, // 10 MB JIT code
      stackSizeMb: options?.resourceLimits?.stackSizeMb ?? 4, // 4 MB stack
    },
  });

  try {
    let timer: NodeJS.Timeout;
    let done = false;

    const once = (fn: () => unknown) => {
      if (!done) {
        done = true;
        if (timer) {
          clearTimeout(timer);
        }
        fn();
      }
    };

    // Race between rendering and timeout
    return await Promise.race([
      // Rendering promise
      new Promise<string>((resolve, reject) => {
        worker.on('message', (message: WorkerReply) => {
          const data = message.success ? message.result : undefined;
          if (data !== undefined) {
            once(() => resolve(data));
          } else {
            once(() => reject(new Error(message.error || 'Unknown worker error')));
          }
        });

        worker.on('error', (error: Error) => {
          once(() => reject(new Error(`Worker error: ${error.message}`, { cause: error })));
        });

        worker.on('exit', (code) => {
          once(() => reject(new Error(`Worker stopped with exit code ${code}`)));
        });
      }),

      // Timeout promise
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          once(() => reject(new Error(`Rendering timeout after ${timeout}ms`)));
        }, timeout);
      }),
    ]);
  } catch (error) {
    // Enhance error messages
    if (!(error instanceof Error)) {
      throw new Error('Unknown rendering error', { cause: error });
    }
    if (error.message.includes('Worker terminated')) {
      throw new Error('Rendering exceeded memory limits', { cause: error });
    }
    throw error;
  } finally {
    // Clean termination
    try {
      await worker.terminate();
    } catch {
      // ignore
    }
  }
};
