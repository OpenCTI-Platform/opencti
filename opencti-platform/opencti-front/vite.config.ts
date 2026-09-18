import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import relay from 'vite-plugin-relay';
import monacoEditorPluginImport from 'vite-plugin-monaco-editor';
import { spawn } from 'node:child_process';
import * as path from 'node:path';

// ESM/CJS interop: Vite's loader nests the callable under `.default`, knip's hands it over
// directly. Without the fallback knip cannot load this config at all.
const monacoEditorPlugin = (monacoEditorPluginImport as unknown as {default: typeof monacoEditorPluginImport}).default
  ?? monacoEditorPluginImport;

const runRelayCompiler = () => new Promise<void>((resolve, reject) => {
  const relayProcess = spawn('yarn', ['relay'], {
    cwd: __dirname,
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env },
  });

  relayProcess.stdout?.on('data', (chunk) => process.stdout.write(chunk));
  relayProcess.stderr?.on('data', (chunk) => process.stderr.write(chunk));

  relayProcess.on('error', (error) => {
    reject(error);
  });

  relayProcess.on('close', (code) => {
    if (code === 0) {
      resolve();
    } else {
      reject(new Error(`Relay compiler exited with code ${code}`));
    }
  });
});

const watchGraphQL = process.env.WATCH_GRAPHQL === 'true';


// https://vitejs.dev/config/
export default defineConfig(({ mode, command }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const configuredFrontEndPort = env.FRONT_END_PORT?.trim();
  const frontEndPort = configuredFrontEndPort ? Number.parseInt(configuredFrontEndPort, 10) : 3000;

  if (configuredFrontEndPort && (!/^\d+$/.test(configuredFrontEndPort) || frontEndPort < 1 || frontEndPort > 65535)) {
    throw new Error(`FRONT_END_PORT must be an integer between 1 and 65535, got "${env.FRONT_END_PORT}"`);
  }

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
    base: command === 'serve' && basePath ? `${basePath}/` : './',
    build: {
      sourcemap: true,
    },

    legacy: {
      // need for some modules that are still CJS
      inconsistentCjsInterop: true,
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
            .replace(/%APP_FAVICON%/g, `${basePath}/assets/static/favicon.png`),
      },
      (watchGraphQL ? {
        name: 'relay-schema-watcher',
        apply: 'serve',
        configureServer(server) {
          const schemaPath = path.resolve(__dirname, './src/schema/relay.schema.graphql');
          
          // Watch the schema file
          server.watcher.add(schemaPath);
          
          let relayTimeout: NodeJS.Timeout | null = null;
          let isRelayRunning = false;
          let pendingRerun = false;

          const runRelay = async () => {
            isRelayRunning = true;
            try {
              console.log('\n🔄 GraphQL schema changed, running relay compiler...');
              await runRelayCompiler();
              console.log('✅ Relay compiler finished successfully');

              // Only trigger reload after successful completion
              console.log('🔄 Triggering full reload');
              server.ws.send({ type: 'full-reload', path: '*' });
              console.log('✅ Frontend is up to date with GraphQL schema changes\n');
            } catch (error) {
              console.error('❌ Relay compiler error:', error);
              console.log('⚠️  Skipping reload due to error\n');
            } finally {
              isRelayRunning = false;
              if (pendingRerun) {
                pendingRerun = false;
                runRelay();
              }
            }
          };

          server.watcher.on('change', async (file) => {
            if (path.resolve(file) === schemaPath) {
              // If relay is already running, queue one more run for when it finishes
              if (isRelayRunning) {
                console.log('⏳ Relay compiler already running, queuing rerun...');
                pendingRerun = true;
                return;
              }

              // Debounce to avoid multiple rapid runs
              if (relayTimeout) clearTimeout(relayTimeout);

              relayTimeout = setTimeout(() => {
                runRelay();
              }, 300);
            }
          });
        },
      }: undefined),
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
      port: frontEndPort,
      watch: watchGraphQL ? {
        ignored: [
          '**/__generated__/**',
        ],
      } : undefined,
      proxy: {
        [`${basePath}/logout`]: backProxy(),
        [`${basePath}/stream`]: backProxy(),
        [`${basePath}/storage`]: backProxy(),
        [`${basePath}/catalog`]: backProxy(),
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
