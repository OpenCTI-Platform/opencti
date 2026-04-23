/**
 * Monaco Editor worker configuration for Vite.
 *
 * GraphiQL v5 uses Monaco Editor which relies on Web Workers for language
 * features (autocompletion, validation, hover). Monaco must know how to
 * instantiate these workers via `globalThis.MonacoEnvironment.getWorker`.
 *
 * Uses the `new Worker(new URL(...))` pattern which Vite handles natively
 * in both dev and production, without the `?worker` suffix that trips up
 * esbuild's dependency scanner.
 *
 * This module MUST be imported before any GraphiQL / Monaco code runs.
 */
window.MonacoEnvironment = {
  getWorker(_workerId: string, label: string) {
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
  },
};
