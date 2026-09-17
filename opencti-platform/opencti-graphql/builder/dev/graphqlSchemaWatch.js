import { spawn } from 'node:child_process';
import chokidar from 'chokidar';

// Only watch directories that contain files affecting graphql-codegen output.
const WATCH_PATHS = [
  'src',
  'config/schema',
  'builder/schema',
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

// Only extensions that can change the graphql-codegen output:
//   .graphql/.gql — schema definitions read by graphql-codegen
//   .js           — builder/schema/ scripts that generate the schema
// .ts files are TypeScript implementation — they never affect the schema.
const WATCHED_EXTENSIONS = new Set([
  '.graphql', '.gql', '.js',
]);

// .js files only affect the generated schema when they live under builder/schema
// (the scripts that produce it). .js files anywhere else in the watched tree
// (e.g. under src) are not schema/codegen related and must not trigger a rebuild.
const JS_SCHEMA_SCRIPTS_DIR = 'builder/schema/';

let isBuilding = false;
let pendingBuild = false;
let debounceTimeout = null;
let activeBuildPath = null;
let queuedBuildPath = null;
let currentSchemaProcess = null;

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

  const normalized = normalizePath(filePath);
  const dotIndex = normalized.lastIndexOf('.');
  const extension = dotIndex >= 0 ? normalized.slice(dotIndex) : '';
  if (!WATCHED_EXTENSIONS.has(extension)) {
    return false;
  }
  // Narrow .js down to the schema-generating scripts only; other .js files
  // (e.g. under src) don't affect the graphql-codegen output.
  if (extension === '.js') {
    return normalized.includes(JS_SCHEMA_SCRIPTS_DIR);
  }
  return true;
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
  currentSchemaProcess = schemaProcess;

  schemaProcess.on('exit', (code) => {
    isBuilding = false;
    activeBuildPath = null;
    if (currentSchemaProcess === schemaProcess) {
      currentSchemaProcess = null;
    }

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
    if (currentSchemaProcess === schemaProcess) {
      currentSchemaProcess = null;
    }
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
  }, 300);
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

  const shutdown = async () => {
    await watcher.close();
    // Terminate any in-flight schema build so it doesn't get orphaned when the
    // dev watcher exits mid-build.
    if (currentSchemaProcess && currentSchemaProcess.exitCode === null) {
      currentSchemaProcess.kill('SIGTERM');
    }
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  console.log('[GRAPHQL-WATCH] Watching GraphQL sources for changes...');
}

function main() {
  runSchemaBuild('initial');
  startWatcher();
}

main();
