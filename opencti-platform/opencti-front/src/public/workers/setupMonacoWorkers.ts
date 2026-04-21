/**
 * Monaco Editor worker configuration for Vite (dev) and esbuild (prod).
 *
 * GraphiQL v5 uses Monaco Editor which relies on Web Workers for language
 * features (autocompletion, validation, hover). Monaco must know how to
 * instantiate these workers via `globalThis.MonacoEnvironment.getWorker`.
 *
 * - In Vite dev  (import.meta.env.DEV === true): uses `new Worker(new URL(...))`
 *   which Vite handles natively, building each worker on demand.
 *
 * - In production (import.meta.env.DEV === false, set via esbuild `define`):
 *   workers are pre-built as separate bundles to `/static/workers/` by prod.js.
 *   We reference them by absolute URL using window.BASE_PATH (set by the server).
 *   The DEV branch is dead-code eliminated by esbuild so import.meta.url is
 *   never evaluated in IIFE mode.
 *
 * This module MUST be imported before any GraphiQL / Monaco code runs.
 */

const basePath = ((window as Window & { BASE_PATH?: string }).BASE_PATH ?? '').replace(/\/$/, '');

window.MonacoEnvironment = {
  getWorker(_workerId: string, label: string) {
    if (import.meta.env?.DEV) {
      // Vite dev: use module workers with native URL resolution
      if (label === 'json') {
        return new Worker(
          new URL('./json.worker.ts', import.meta.url),
          { type: 'module' },
        );
      }
      if (label === 'graphql') {
        return new Worker(
          new URL('./graphql.worker.ts', import.meta.url),
          { type: 'module' },
        );
      }
      return new Worker(
        new URL('./editor.worker.ts', import.meta.url),
        { type: 'module' },
      );
    }

    // Production: workers are pre-built to /static/workers/ by prod.js
    if (label === 'json') {
      return new Worker(`${basePath}/static/workers/json.worker.js`);
    }
    if (label === 'graphql') {
      return new Worker(`${basePath}/static/workers/graphql.worker.js`);
    }
    return new Worker(`${basePath}/static/workers/editor.worker.js`);
  },
};
