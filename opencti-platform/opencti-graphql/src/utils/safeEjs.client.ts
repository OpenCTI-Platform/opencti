import { Worker } from 'worker_threads';
import * as path from 'path';
import type { Data } from 'ejs';
import type { SafeRenderOptions } from './safeEjs';
import type { WorkerReply } from './safeEjs.worker';

export type WorkerOptions = {
  timeout?: number,
  useJsonEscape?: boolean,
  resourceLimits?: {
    maxOldGenerationSizeMb?: number
    maxYoungGenerationSizeMb: number,
    codeRangeSizeMb: number,
    stackSizeMb: number,
  }
};

export const safeRender = async (template: string, data: Data, options?: SafeRenderOptions & WorkerOptions): Promise<string> => {
  // Handle empty template directly without worker
  if (!template) {
    return '';
  }

  const timeout = options?.timeout ?? 5000; // Default 5 seconds

  // Determine the correct worker path based on the environment
  let workerPath: string;

  if (__filename.endsWith('.js')) {
    // Production: running from build directory
    // The worker is built to build/safeEjs.worker.js (at the root of build)
    workerPath = path.join(__dirname, 'safeEjs.worker.js');
  } else {
    // Development/Test: running from source directory (src/utils/)
    // The worker is built to opencti-graphql/build/safeEjs.worker.js
    // From src/utils, go up to opencti-graphql root, then into build
    workerPath = path.join(__dirname, '..', '..', 'build', 'safeEjs.worker.js');
  }

  // Handle escape function - remove it from options if it exists (can't be serialized)
  const workerOptions = { ...options };
  if (workerOptions.escape) {
    delete workerOptions.escape;
  }

  const worker = new Worker(workerPath, {
    workerData: { template, data, options: workerOptions, useJsonEscape: options?.useJsonEscape },
    resourceLimits: {
      maxOldGenerationSizeMb: options?.resourceLimits?.maxOldGenerationSizeMb ?? 50, // 50 MB heap
      maxYoungGenerationSizeMb: options?.resourceLimits?.maxYoungGenerationSizeMb ?? 10, // 10 MB new space
      codeRangeSizeMb: options?.resourceLimits?.codeRangeSizeMb ?? 10, // 10 MB JIT code
      stackSizeMb: options?.resourceLimits?.stackSizeMb ?? 4, // 4 MB stack
    },
  });

  try {
    // Track worker error to preserve it in case of timeout
    let workerError: Error | undefined;

    // Race between rendering and timeout
    const result = await Promise.race([
      // Rendering promise
      new Promise<string>((resolve, reject) => {
        worker.on('message', (message: WorkerReply) => {
          if (message.success && message.result !== undefined) {
            resolve(message.result);
          } else {
            const error = new Error(message.error || 'Unknown worker error');
            workerError = error;
            reject(error);
          }
        });

        worker.on('error', (error) => {
          const workerErr = new Error(`Worker error: ${error.message}`);
          workerError = workerErr;
          reject(workerErr);
        });

        worker.on('exit', (code) => {
          if (code !== 0 && code !== null) {
            const exitError = new Error(`Worker stopped with exit code ${code}`);
            workerError = exitError;
            reject(exitError);
          }
        });
      }),

      // Timeout promise
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          // Preserve worker error if it exists, otherwise report timeout
          reject(workerError ?? new Error(`Rendering timeout after ${timeout}ms`));
        }, timeout);
      })
    ]);

    return result;
  } catch (error) {
    // Enhance error messages
    if (!(error instanceof Error)) {
      throw new Error('Unknown rendering error');
    }
    if (error.message.includes('Worker terminated')) {
      throw new Error('Rendering exceeded memory limits');
    }
    throw error;
  } finally {
    // Clean termination
    await worker.terminate();
  }
};
