import type { Data } from 'ejs';
import type { SafeRenderOptions } from './safeEjs';
import { renderInPool } from './safeEjs.pool';

export type WorkerOptions = {
  timeout?: number;
  useJsonEscape?: boolean;
};

export const safeRender = async (template: string, data: Data, options?: SafeRenderOptions & WorkerOptions): Promise<string> => {
  // Handle empty template directly without worker
  if (!template) {
    return '';
  }

  const timeout = options?.timeout ?? 5000; // Default 5 seconds

  // Handle escape function - remove it from options if it exists (can't be serialized)
  const workerOptions = { ...options };
  if (workerOptions.escape) {
    delete workerOptions.escape;
  }

  try {
    return await renderInPool({ template, data, options: workerOptions, useJsonEscape: options?.useJsonEscape }, timeout);
  } catch (error) {
    // Enhance error messages
    if (!(error instanceof Error)) {
      throw new Error('Unknown rendering error', { cause: error });
    }
    if (error.message.includes('Worker terminated')) {
      throw new Error('Rendering exceeded memory limits', { cause: error });
    }
    throw error;
  }
};
