const { spawn } = require('child_process');
const chokidar = require('chokidar');

const WATCH_PATHS = [
  'src',
  'builder/schema',
  'script',
];

const IGNORED_PATTERNS = [
  '**/node_modules/**',
  '**/.yarn/**',
  '**/logs/**',
  '**/__generated__/**',
  '**/generated/**',
  '**/*.log',
  '**/*.tmp',
];

const WATCHED_EXTENSIONS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.graphql', '.gql', '.json', '.yaml', '.yml',
]);

let isBuilding = false;
let pendingBuild = false;
let debounceTimeout = null;
let activeBuildPath = null;
let queuedBuildPath = null;

const GENERATED_DIR_MARKERS = [
  '/src/generated/',
  'src/generated/',
];

const GENERATED_FILE_MARKERS = [
  '/graphql.schema.json',
  'graphql.schema.json',
];

function normalizePath(filePath) {
  return filePath.replace(/\\/g, '/');
}

function isGeneratedOutput(filePath) {
  const normalized = normalizePath(filePath);
  if (GENERATED_DIR_MARKERS.some((marker) => normalized.includes(marker))) {
    return true;
  }
  return GENERATED_FILE_MARKERS.some((marker) => normalized.endsWith(marker));
}

function shouldTriggerBuild(filePath) {
  if (isGeneratedOutput(filePath)) {
    return false;
  }

  const dotIndex = filePath.lastIndexOf('.');
  const extension = dotIndex >= 0 ? filePath.slice(dotIndex) : '';
  return WATCHED_EXTENSIONS.has(extension);
}

function runSchemaBuild(reason = 'change', triggerPath = null) {
  if (isBuilding) {
    // Editors can emit multiple events for the same save (change/unlink/add).
    // Do not queue another build if the trigger is the same file already being processed.
    if (triggerPath && activeBuildPath && normalizePath(triggerPath) === normalizePath(activeBuildPath)) {
      return;
    }
    pendingBuild = true;
    queuedBuildPath = triggerPath || queuedBuildPath;
    return;
  }

  isBuilding = true;
  activeBuildPath = triggerPath;
  console.log(`[GRAPHQL-WATCH] Running GraphQL schema build (${reason})...`);

  const schemaProcess = spawn('yarn', ['build:schema'], {
    stdio: ['inherit', 'inherit', 'inherit'],
    shell: false,
    env: { ...process.env },
  });

  schemaProcess.on('exit', (code) => {
    isBuilding = false;
    activeBuildPath = null;

    if (code === 0) {
      console.log('[GRAPHQL-WATCH] GraphQL schema build completed');
    } else {
      console.error(`[GRAPHQL-WATCH] GraphQL schema build exited with code ${code}`);
    }

    if (pendingBuild) {
      pendingBuild = false;
      const nextPath = queuedBuildPath;
      queuedBuildPath = null;
      runSchemaBuild('queued', nextPath);
    }
  });

  schemaProcess.on('error', (err) => {
    isBuilding = false;
    activeBuildPath = null;
    console.error('[GRAPHQL-WATCH] GraphQL build failed:', err);

    if (pendingBuild) {
      pendingBuild = false;
      const nextPath = queuedBuildPath;
      queuedBuildPath = null;
      runSchemaBuild('queued-after-error', nextPath);
    }
  });
}

function scheduleBuild(eventName, filePath) {
  if (!shouldTriggerBuild(filePath)) {
    return;
  }

  if (debounceTimeout) {
    clearTimeout(debounceTimeout);
  }

  debounceTimeout = setTimeout(() => {
    runSchemaBuild(`${eventName}: ${filePath}`, filePath);
  }, 200);
}

function startWatcher() {
  const watcher = chokidar.watch(WATCH_PATHS, {
    ignoreInitial: true,
    ignored: IGNORED_PATTERNS,
    awaitWriteFinish: {
      stabilityThreshold: 120,
      pollInterval: 40,
    },
  });

  watcher
    .on('add', (filePath) => scheduleBuild('add', filePath))
    .on('change', (filePath) => scheduleBuild('change', filePath))
    .on('unlink', (filePath) => scheduleBuild('unlink', filePath))
    .on('error', (err) => {
      console.error('[GRAPHQL-WATCH] File watcher error:', err);
    });

  process.on('SIGINT', async () => {
    await watcher.close();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await watcher.close();
    process.exit(0);
  });

  console.log('[GRAPHQL-WATCH] Watching GraphQL sources for changes...');
}

function main() {
  runSchemaBuild('initial');
  startWatcher();
}

main();
