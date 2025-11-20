import { parentPort, workerData } from 'worker_threads';
import type { Data } from 'ejs';
import { safeRender } from './safeEjs';
import type { SafeRenderOptions } from './safeEjs';

export interface WorkerRequest {
  template: string;
  data: Data;
  options?: SafeRenderOptions;
  useJsonEscape?: boolean;
}

export interface WorkerReply {
  success: boolean;
  result?: string;
  error?: string;
}

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
  const { template, data, options, useJsonEscape } = workerData as WorkerRequest;

  // Reconstruct functions from serialized data
  const reconstructedData = reconstructData(data);

  // Add escape function if needed
  const safeEjsOptions = { ...options };
  if (useJsonEscape) {
    // Recreate the escape function for JSON stringification
    safeEjsOptions.escape = (value: any) => {
      const result = JSON.stringify(value);
      return result.startsWith('"') && result.endsWith('"') ? result.slice(1, -1) : result;
    };
  }

  // Use the core logic from safeEjs (await in case it returns a Promise)
  const result = await safeRender(template, reconstructedData, safeEjsOptions);
  // Send result back to main thread
  const message: WorkerReply = {
    success: true,
    result
  };
  parentPort?.postMessage(message);
};

executeWorker().catch((error) => {
  // Send error back to main thread
  const message: WorkerReply = {
    success: false,
    error: error instanceof Error ? error.message : 'Unknown error'
  };
  parentPort?.postMessage(message);
});
