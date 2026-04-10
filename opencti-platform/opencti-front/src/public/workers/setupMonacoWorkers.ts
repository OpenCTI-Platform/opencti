/**
 * Monaco Editor worker configuration for Vite.
 *
 * GraphiQL v5 uses Monaco Editor which relies on Web Workers for language
 * features (autocompletion, validation, hover). Monaco must know how to
 * instantiate these workers via `globalThis.MonacoEnvironment.getWorker`.
 *
 * The wrapper `.js` files live in project source (not node_modules) so that
 * Vite's `?worker` plugin can fully control bundling and module resolution,
 * avoiding the esbuild `optimizeDeps` issue with `?worker` suffixes.
 *
 * This module MUST be imported before any GraphiQL / Monaco code runs.
 */
import EditorWorker from './editor.worker.js?worker';
import JsonWorker from './json.worker.js?worker';
import GraphQLWorker from './graphql.worker.js?worker';

window.MonacoEnvironment = {
  getWorker(_workerId: string, label: string) {
    if (label === 'json') {
      return new JsonWorker();
    }
    if (label === 'graphql') {
      return new GraphQLWorker();
    }
    return new EditorWorker();
  },
};
