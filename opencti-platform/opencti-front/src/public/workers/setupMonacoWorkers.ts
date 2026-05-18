/**
 * Monaco Editor worker configuration for the GraphiQL Playground.
 *
 * GraphiQL v5 uses Monaco Editor which relies on Web Workers for language
 * features (autocompletion, validation, hover). Monaco must know how to
 * instantiate these workers via `globalThis.MonacoEnvironment.getWorker`.
 *
 * Two build pipelines:
 *
 * - Vite dev (`yarn dev`): `vite-plugin-monaco-editor` is configured in
 *   `vite.config.mts`. It bundles the workers with esbuild and injects a
 *   `<script>` in `index.html` that sets `window.MonacoEnvironment` BEFORE any
 *   app code runs. The code below detects that and becomes a no-op.
 *
 * - esbuild (`yarn start` / `yarn build`): the workers are pre-built as IIFE
 *   bundles into `static/workers/` by `prod.js` / `dev.js`. The code below
 *   wires `MonacoEnvironment` to load those bundles from the public URL.
 *
 * This module MUST be imported before any GraphiQL / Monaco code runs.
 */

if (!window.MonacoEnvironment) {
  const basePath = ((window as Window & { BASE_PATH?: string }).BASE_PATH ?? '').replace(/\/$/, '');
  window.MonacoEnvironment = {
    getWorker(_workerId: string, label: string) {
      const name = label === 'json' ? 'json' : label === 'graphql' ? 'graphql' : 'editor';
      return new Worker(`${basePath}/static/workers/${name}.worker.js`);
    },
  };
}
