import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import relay from 'vite-plugin-relay';
import monacoEditorPluginImport from 'vite-plugin-monaco-editor';

// Handle ESM/CJS interop for vite-plugin-monaco-editor
const monacoEditorPlugin = (monacoEditorPluginImport as unknown as {default: typeof monacoEditorPluginImport}).default;

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');

  // Support APP__BASE_PATH from .env* files (via loadEnv) or from process.env (e.g. set by test scripts).
  // Normalize: ensure leading slash, strip trailing slash.
  const rawBasePath = env.APP__BASE_PATH ?? process.env.APP__BASE_PATH ?? '';
  const basePath = rawBasePath && rawBasePath !== '/'
    ? `/${rawBasePath.replace(/^\/|\/$/g, '')}`
    : '';

  const backProxy = (ws = false) => ({
    target: env.BACK_END_URL ?? 'http://localhost:4000',
    changeOrigin: true,
    ws,
  });

  return {
    base: './',
    build: {
      sourcemap: true,
    },

    legacy: {
      // need for some modules that are still CJS
      inconsistentCjsInterop: true,
    },

    define: {
      // Workaround to circumvent usage of process.env in react-draggable.
      // To remove once https://github.com/react-grid-layout/react-draggable/issues/806 is addressed.
      'process.env.DRAGGABLE_DEBUG': JSON.stringify(process.env.DRAGGABLE_DEBUG === 'true'),
    },

    resolve: {
      tsconfigPaths: true,
      extensions: ['.tsx', '.jsx', '.ts', '.js', '.json'],
    },

    plugins: [
      {
        name: 'html-transform',
        enforce: 'pre',
        apply: 'serve',
        transformIndexHtml: (html) =>
          html.replace(/%BASE_PATH%/g, basePath)
            .replace(/%APP_SCRIPT_SNIPPET%/g,  '')
            .replace(/%APP_TITLE%/g, 'OpenCTI Dev')
            .replace(/%APP_DESCRIPTION%/g, 'OpenCTI Development platform')
            .replace(/%APP_FAVICON%/g, `./assets/static/favicon.png`),
      },
      react(),
      relay,
      monacoEditorPlugin({
        publicPath: 'assets/monaco-editor',
        languageWorkers: ['editorWorkerService', 'json'],
        customWorkers: [
          {
            label: 'graphql',
            entry: 'monaco-graphql/esm/graphql.worker.js',
          },
        ],
      }),
    ],

    server: {
      port: 3000,
      proxy: {
        [`${basePath}/logout`]: backProxy(),
        [`${basePath}/stream`]: backProxy(),
        [`${basePath}/storage`]: backProxy(),
        [`${basePath}/schema`]: backProxy(),
        '^/.*/embedded/.*': backProxy(),
        [`${basePath}/taxii2`]: backProxy(),
        [`${basePath}/feeds`]: backProxy(),
        [`${basePath}/graphql`]: backProxy(true),
        [`${basePath}/auth`]: backProxy(),
        [`${basePath}/chatbot`]: backProxy(),
        [`${basePath}/maps`]: backProxy(),
      },
    },
  };
});
