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

export const customEscapeFunction = (value: any): string => {
  if (Array.isArray(value) && value.length === 0) {
    return '';
  }
  const result = JSON.stringify(value);
  // Handle undefined result from JSON.stringify (e.g., when value is undefined or a function)
  if (result === undefined) {
    return '';
  }
  return result.startsWith('"') && result.endsWith('"')
    ? result.slice(1, -1)
    : result;
};

// Main worker execution
const executeWorker = async () => {
  const { template, data, options, useJsonEscape } = workerData as WorkerRequest;

  // Add escape function if needed
  const safeEjsOptions = { ...options };
  if (useJsonEscape) {
    // Recreate the escape function for JSON stringification
    safeEjsOptions.escape = customEscapeFunction;
  }

  // Use the core logic from safeEjs (await in case it returns a Promise)
  const result = await safeRender(template, data, safeEjsOptions);
  // Send result back to main thread
  const message: WorkerReply = {
    success: true,
    result,
  };
  parentPort?.postMessage(message);
};

executeWorker().catch((error) => {
  // Send error back to main thread
  const message: WorkerReply = {
    success: false,
    error: error instanceof Error ? error.message : 'Unknown error',
  };
  parentPort?.postMessage(message);
});
