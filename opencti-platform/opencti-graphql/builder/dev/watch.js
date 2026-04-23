const { spawn } = require('child_process');
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
let esbuildStdoutBuffer = '';

function tryStartAfterInitialBuild(line) {
  if (initialBuildDone) {
    return;
  }

  if (line.includes('✅ Initial build complete')) {
    initialBuildDone = true;
    startAppWatch();
    startGraphQLSchemaWatch();
  }
}

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

function startAppWatch() {
  if (appProcess) {
    return;
  }

  console.log('[WATCH] Starting backend with node --watch...');
  appProcess = spawn('node', [
    '--watch',
    '--watch-path=build/back.js',
    '--watch-kill-signal=SIGTERM',
    '--watch-preserve-output',
    '--enable-source-maps',
    'build/back.js',
  ], {
    cwd: CONFIG.projectRoot,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    env: { ...process.env, NODE_ENV: 'development', HOT_RELOAD_WATCH: 'true' },
  });

  pipeFormattedOutput(appProcess.stdout, process.stdout);
  pipeFormattedOutput(appProcess.stderr, process.stderr);

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

function handleEsbuildOutput(data) {
  const output = data.toString();
  process.stdout.write(output);

  const text = `${esbuildStdoutBuffer}${output}`;
  const lines = text.split('\n');
  esbuildStdoutBuffer = lines.pop() || '';

  for (const line of lines) {
    tryStartAfterInitialBuild(line);
  }
}

function flushEsbuildOutputBuffer() {
  if (esbuildStdoutBuffer.length === 0) {
    return;
  }

  tryStartAfterInitialBuild(esbuildStdoutBuffer);
  esbuildStdoutBuffer = '';
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
  esbuildProcess = spawn('node', ['builder/dev/dev.js', '--watch'], {
    cwd: CONFIG.projectRoot,
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: false,
    env: { ...process.env, NODE_ENV: 'development' },
  });

  esbuildProcess.stdout.on('data', handleEsbuildOutput);
  esbuildProcess.stdout.on('end', flushEsbuildOutputBuffer);
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
