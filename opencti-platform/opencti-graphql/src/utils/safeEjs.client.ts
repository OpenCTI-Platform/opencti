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

// Helper to serialize functions and validate data
const prepareDataForWorker = (data: Data): Data => {
  const forbidden = ['eval', 'Function', 'constructor', '__proto__', 'prototype', 'freeze'];

  // Track function results to create a wrapper object
  const functionMap = new Map<string, any>();
  let functionCounter = 0;

  const serialize = (obj: any, currentPath: string = ''): any => {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'function') {
      // Functions can't be passed to workers, so we create a special marker
      // and store the function's result
      functionCounter += 1;
      const funcId = `__func_${functionCounter}__`;
      try {
        functionMap.set(funcId, obj());
      } catch {
        functionMap.set(funcId, undefined);
      }
      // Return a special object that the worker can recognize
      return { __isFunction: true, __funcId: funcId, __funcResult: functionMap.get(funcId) };
    }

    if (Array.isArray(obj)) {
      return obj.map((item, index) => serialize(item, `${currentPath}[${index}]`));
    }

    if (typeof obj === 'object') {
      const result: any = {};
      Object.entries(obj).forEach(([key, value]) => {
        // Check for forbidden properties
        if (forbidden.includes(key)) {
          throw new Error(`Inaccessible property in data: ${key}`);
        }
        result[key] = serialize(value, currentPath ? `${currentPath}.${key}` : key);
      });
      return result;
    }

    return obj;
  };

  return serialize(data);
};

export const safeRender = async (template: string, data: Data, options?: SafeRenderOptions & WorkerOptions): Promise<string> => {
  // Handle empty template directly without worker
  if (!template) {
    return '';
  }

  // Prepare and validate data
  let serializedData: Data;
  try {
    serializedData = prepareDataForWorker(data);
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : 'Invalid data');
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
    workerData: { template, data: serializedData, options: workerOptions, useJsonEscape: options?.useJsonEscape },
    resourceLimits: {
      maxOldGenerationSizeMb: options?.resourceLimits?.maxOldGenerationSizeMb ?? 50, // 50 MB heap
      maxYoungGenerationSizeMb: options?.resourceLimits?.maxYoungGenerationSizeMb ?? 10, // 10 MB new space
      codeRangeSizeMb: options?.resourceLimits?.codeRangeSizeMb ?? 10, // 10 MB JIT code
      stackSizeMb: options?.resourceLimits?.stackSizeMb ?? 4, // 4 MB stack
    },
  });

  try {
    // Race between rendering and timeout
    const result = await Promise.race([
      // Rendering promise
      new Promise<string>((resolve, reject) => {
        worker.on('message', (message: WorkerReply) => {
          if (message.success && message.result !== undefined) {
            resolve(message.result);
          } else {
            reject(new Error(message.error || 'Unknown worker error'));
          }
        });

        worker.on('error', (error) => {
          reject(new Error(`Worker error: ${error.message}`));
        });

        worker.on('exit', (code) => {
          if (code !== 0 && code !== null) {
            reject(new Error(`Worker stopped with exit code ${code}`));
          }
        });
      }),

      // Timeout promise
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Rendering timeout after ${timeout}ms`));
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
