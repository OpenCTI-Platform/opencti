const { spawn, fork } = require('child_process');
const path = require('path');
const { formatOutput } = require('./logsFormat');

const CONFIG = {
  graphql: process.argv.includes('--graphql'),
  projectRoot: path.resolve(__dirname, '..', '..'),
};

let initialBuildDone = false;
let shuttingDown = false;
let appProcess = null;
let esbuildProcess = null;
let graphQLWatchProcess = null;

function pipeFormattedOutput(stream, outputStream) {
  if (!stream) {
    return;
  }

  let buffer = '';
  stream.on('data', (chunk) => {
    const text = `${buffer}${chunk.toString()}`;
    const lines = text.split('\n');
    buffer = lines.pop() || '';

    if (lines.length > 0) {
      const formatted = formatOutput(lines.join('\n'));
      if (formatted) {
        outputStream.write(`${formatted}\n`);
      }
    }
  });

  stream.on('end', () => {
    if (buffer.trim().length > 0) {
      const formatted = formatOutput(buffer);
      if (formatted) {
        outputStream.write(`${formatted}\n`);
      }
    }
  });
}

function startApp() {
  console.log('[WATCH] Starting backend...');
  appProcess = spawn('node', [
    '--enable-source-maps',
    'build/back.js',
  ], {
    cwd: CONFIG.projectRoot,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    env: { ...process.env, NODE_ENV: 'development', HOT_RELOAD_WATCH: 'true' },
  });

  pipeFormattedOutput(appProcess.stdout, process.stdout);
  // Pipe stderr directly so node internal messages are never suppressed
  appProcess.stderr.on('data', (data) => process.stderr.write(data));

  appProcess.on('exit', (code) => {
    appProcess = null;
    if (!shuttingDown && code !== 0 && code !== null) {
      console.error(`[WATCH] backend process exited with code ${code}`);
      shutdown(1);
    }
  });

  appProcess.on('error', (err) => {
    console.error('[WATCH] Failed to start backend process:', err);
    shutdown(1);
  });
}

function startAppWatch() {
  startApp();
}

function restartApp() {
  console.log('[WATCH] Restarting backend...');
  if (appProcess) {
    appProcess.once('exit', () => startApp());
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

  graphQLWatchProcess.on('exit', (code) => {
    graphQLWatchProcess = null;
    if (!shuttingDown && code !== 0 && code !== null) {
      console.error(`[WATCH] GraphQL schema watcher exited with code ${code}`);
      shutdown(1);
    }
  });

  graphQLWatchProcess.on('error', (err) => {
    console.error('[WATCH] Failed to start GraphQL schema watcher:', err);
    shutdown(1);
  });
}

function startEsbuildWatch() {
  esbuildProcess = fork(require.resolve('./dev.js'), ['--watch'], {
    cwd: CONFIG.projectRoot,
    silent: true, // captures stdio so we can pipe/format it
    execArgv: [],
    env: { ...process.env, NODE_ENV: 'development' },
  });

  // Receive IPC messages from dev.js
  esbuildProcess.on('message', (msg) => {
    if (!msg) return;
    if (msg.type === 'initial-build-complete' && !initialBuildDone) {
      console.log('[WATCH] Received initial-build-complete IPC, starting app...');
      initialBuildDone = true;
      startAppWatch();
      startGraphQLSchemaWatch();
    } else if (msg.type === 'rebuild-complete') {
      restartApp();
    }
  });

  esbuildProcess.stdout.on('data', handleEsbuildOutput);
  esbuildProcess.stderr.on('data', (data) => process.stderr.write(data));

  esbuildProcess.on('exit', (code) => {
    esbuildProcess = null;
    if (!shuttingDown && code !== 0 && code !== null) {
      console.error(`[WATCH] esbuild watcher exited with code ${code}`);
      shutdown(1);
    }
  });

  esbuildProcess.on('error', (err) => {
    console.error('[WATCH] Failed to start esbuild watcher:', err);
    shutdown(1);
  });
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

function main() {
  console.log('\n🚀 Starting dev OpenCTI...');
  console.log(CONFIG.graphql ? '• with GraphQL hot reload\n' : '• without GraphQL hot reload\n');

  startEsbuildWatch();

  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));
}

main();
