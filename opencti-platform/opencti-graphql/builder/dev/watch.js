#!/usr/bin/env node

import { spawn, fork } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const CONFIG = {
  graphql: process.argv.includes('--graphql'),
  projectRoot: path.resolve(__dirname, '..', '..'),
};

let initialBuildDone = false;
let shuttingDown = false;
let appProcess = null;
let esbuildProcess = null;
let graphQLWatchProcess = null;
let pendingRestart = false;

// Shared lifecycle handlers to avoid repeating the same log+shutdown shape
// across appProcess, graphQLWatchProcess and esbuildProcess.
function onProcessError(label) {
  return (err) => {
    console.error(`[WATCH] Failed to start ${label}:`, err);
    shutdown(1);
  };
}

function onFatalExit(label, clearRef) {
  return (code) => {
    clearRef();
    if (!shuttingDown && code !== 0 && code !== null) {
      console.error(`[WATCH] ${label} exited with code ${code}`);
      shutdown(1);
    }
  };
}

function startApp() {
  console.log('[WATCH] Starting backend...');
  appProcess = spawn('node', [
    '--enable-source-maps',
    'build/back.mjs',
  ], {
    cwd: CONFIG.projectRoot,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    env: { ...process.env, NODE_ENV: 'development', HOT_RELOAD_WATCH: 'true' },
  });

  appProcess.stdout.on('data', (data) => process.stdout.write(data));
  appProcess.stderr.on('data', (data) => process.stderr.write(data));

  appProcess.on('exit', (code) => {
    appProcess = null;
    if (!shuttingDown && code !== 0 && code !== null) {
      console.error(`[WATCH] backend process exited with code ${code}, waiting for next successful build...`);
    }
  });

  appProcess.on('error', onProcessError('backend process'));
}

function restartApp() {
  console.log('[WATCH] Restarting backend...');
  if (appProcess) {
    pendingRestart = true;
    appProcess.once('exit', () => {
      if (pendingRestart) {
        pendingRestart = false;
        startApp();
      }
    });
    appProcess.kill('SIGTERM');
  } else {
    startApp();
  }
}

function handleEsbuildOutput(data) {
  const output = data.toString();
  process.stdout.write(output);
}

function startGraphQLSchemaWatch() {
  if (!CONFIG.graphql || graphQLWatchProcess) {
    return;
  }

  console.log('[WATCH] Starting GraphQL schema watch...');

  graphQLWatchProcess = spawn('node', ['builder/dev/graphqlSchemaWatch.js'], {
    cwd: CONFIG.projectRoot,
    stdio: ['inherit', 'inherit', 'inherit'],
    shell: false,
    env: { ...process.env, NODE_ENV: 'development' },
  });

  graphQLWatchProcess.on('exit', onFatalExit('GraphQL schema watcher', () => { graphQLWatchProcess = null; }));
  graphQLWatchProcess.on('error', onProcessError('GraphQL schema watcher'));
}

function startEsbuildWatch() {
  esbuildProcess = fork(path.join(CONFIG.projectRoot, 'builder/builder.js'), ['--development', '--watch'], {
    cwd: CONFIG.projectRoot,
    silent: true, // captures stdio so we can pipe it
    execArgv: [],
    env: { ...process.env, NODE_ENV: 'development' },
  });

  // Receive IPC messages from builder.js
  esbuildProcess.on('message', (msg) => {
    if (!msg) return;
    if (msg.type === 'initial-build-complete' && !initialBuildDone) {
      console.log('[WATCH] Received initial-build-complete IPC, starting app...');
      initialBuildDone = true;
      startApp();
      startGraphQLSchemaWatch();
    } else if (msg.type === 'rebuild-complete') {
      restartApp();
    } else if (msg.type === 'rebuild-failed' && pendingRestart) {
      pendingRestart = false;
      console.log('[WATCH] Build failed while restarting backend, waiting for next successful build...');
    }
  });

  esbuildProcess.stdout.on('data', handleEsbuildOutput);
  esbuildProcess.stderr.on('data', (data) => process.stderr.write(data));

  esbuildProcess.on('exit', onFatalExit('esbuild watcher', () => { esbuildProcess = null; }));
  esbuildProcess.on('error', onProcessError('esbuild watcher'));
}

function stopProcess(proc) {
  if (!proc || proc.killed) {
    return;
  }
  proc.kill('SIGTERM');
}

function shutdown(code = 0) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;

  stopProcess(esbuildProcess);
  stopProcess(appProcess);
  stopProcess(graphQLWatchProcess);
  process.exit(code);
}

// Main entry point
function main() {
  console.log('\n🚀 Starting dev OpenCTI...');
  console.log(CONFIG.graphql ? '• with GraphQL hot reload\n' : '• without GraphQL hot reload\n');

  startEsbuildWatch();

  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));
}

// Start the watch process
main();
