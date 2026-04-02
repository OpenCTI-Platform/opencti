import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import * as path from 'node:path';
import relay from 'vite-plugin-relay';
import { viteStaticCopy } from 'vite-plugin-static-copy';
import monacoEditorPluginImport from 'vite-plugin-monaco-editor';

// Handle ESM/CJS interop for vite-plugin-monaco-editor
const monacoEditorPlugin = (monacoEditorPluginImport as unknown as {default: typeof monacoEditorPluginImport}).default;

const basePath = "";

const backProxy = (ws = false) => ({
  target: process.env.BACK_END_URL ?? 'http://localhost:4000',
  changeOrigin: true,
  ws,
});

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    target: ['chrome58'],
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
    alias: {
      '@components': path.resolve(__dirname, './src/private/components'),
      'src': path.resolve(__dirname, './src'),
      '@common': path.resolve(__dirname, './src/components/common')
    },
    extensions: ['.tsx', '.jsx', '.ts', '.js', '.json'],
  },

  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: 'src/static/ext/*',
          dest: 'static/ext',
          rename: {
            stripBase: true
          }
        }
      ]
    }),
    {
      name: 'html-transform',
      enforce: "pre",
      apply: 'serve',
      transformIndexHtml(html) {
        return html.replace(/%BASE_PATH%/g, basePath)
          .replace(/%APP_SCRIPT_SNIPPET%/g,  '')
          .replace(/%APP_TITLE%/g, "OpenCTI Dev")
          .replace(/%APP_DESCRIPTION%/g, "OpenCTI Development platform")
          .replace(/%APP_FAVICON%/g, `${basePath}/static/ext/favicon.png`)
          .replace(/%APP_MANIFEST%/g, `${basePath}/static/ext/manifest.json`)
      }
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
    })
  ],

  server: {
    port: 3000,
    proxy: {
      '/logout': backProxy(),
      '/stream': backProxy(),
      '/storage': backProxy(),
      '/schema': backProxy(),
      '^/.*/embedded/.*': backProxy(),
      '/taxii2': backProxy(),
      '/feeds': backProxy(),
      '/graphql': backProxy(true),
      '/auth': backProxy(),
      '/static/flags': backProxy(),
      '/chatbot': backProxy(),
    },
  },
});
