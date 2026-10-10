import { parentPort } from 'worker_threads';
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
  return result && result.startsWith('"') && result.endsWith('"')
    ? result.slice(1, -1)
    : result;
};

// The worker stays alive and renders one request at a time, so the pool can hand it to the next
// caller instead of paying for a thread per template.
const executeRequest = async (request: WorkerRequest) => {
  const { template, data, options, useJsonEscape } = request;

  // Add escape function if needed
  const safeEjsOptions = { ...options };
  if (useJsonEscape) {
    // Recreate the escape function for JSON stringification
    safeEjsOptions.escape = customEscapeFunction;
  }

  // Use the core logic from safeEjs (await in case it returns a Promise)
  const result = await safeRender(template, data, safeEjsOptions);
  // Yield a full event-loop turn before replying: setImmediate only fires once the microtask queue
  // has drained, so a template that left an endless microtask loop running never gets here and hits
  // its own render timeout, instead of starving the next render on this reused worker.
  await new Promise<void>((resolve) => setImmediate(resolve));
  return result;
};

parentPort?.on('message', (request: WorkerRequest) => {
  executeRequest(request)
    .then((result) => {
      parentPort?.postMessage({ success: true, result } satisfies WorkerReply);
    })
    .catch((error) => {
      const message: WorkerReply = {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
      parentPort?.postMessage(message);
    });
});
