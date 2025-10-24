import { parentPort, workerData } from 'worker_threads';
import type { Data } from 'ejs';
import { safeRenderCore, type SafeRenderOptions } from './safeEjsCore';

export interface WorkerData {
  template: string;
  data: Data;
  options?: SafeRenderOptions;
}

export interface WorkerMessage {
  success: boolean;
  result?: string;
  error?: string;
}

// Re-export types for backward compatibility
export type { SafeRenderOptions } from './safeEjs';

// Helper to reconstruct functions from serialized data
const reconstructData = (obj: any): any => {
  if (obj === null || obj === undefined) return obj;

  // Check if this is a serialized function
  if (typeof obj === 'object' && obj.__isFunction && obj.__funcResult !== undefined) {
    // Create a function that returns the pre-computed result
    return () => obj.__funcResult;
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => reconstructData(item));
  }

  if (typeof obj === 'object') {
    const result: any = {};
    Object.entries(obj).forEach(([key, value]) => {
      result[key] = reconstructData(value);
    });
    return result;
  }

  return obj;
};

// Main worker execution
const executeWorker = async () => {
  try {
    const { template, data, options } = workerData as WorkerData;

    // Reconstruct functions from serialized data
    const reconstructedData = reconstructData(data);

    // Use the core logic from safeEjs (await in case it returns a Promise)
    const result = await safeRenderCore(template, reconstructedData, options);

    // Send result back to main thread
    const message: WorkerMessage = {
      success: true,
      result
    };
    parentPort?.postMessage(message);
  } catch (error) {
    // Send error back to main thread
    const message: WorkerMessage = {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
    parentPort?.postMessage(message);
  }
};

executeWorker().catch((error) => {
  // Error is already handled inside executeWorker, this is just to satisfy ESLint
  const message: WorkerMessage = {
    success: false,
    error: error instanceof Error ? error.message : 'Unknown error'
  };
  parentPort?.postMessage(message);
});
