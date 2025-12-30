const { spawn } = require('child_process');
const path = require('path');
const { formatOutput } = require('./logsFormat');

const CONFIG = {
  graphql: process.argv.includes('--graphql'),
  projectRoot: path.resolve(__dirname, '..', '..'),
  shutdownTimeout: 35000,
  shutdownDelay: 100,
  restartDelay: 500,
};

let initialBuildDone = false;
let nodemonProcess = null;
let esbuildProcess = null;

function displayStartupMessage() {
  console.log('\n🚀 Starting dev OpenCTI...');

  if (CONFIG.graphql) {
    console.log('• with GraphQL hot reload');
  } else {
    console.log('• without GraphQL hot reload');
  }
  console.log('');
}

function setupNodemonOutputHandlers(process) {
  let platformShutdownResolve = null;
  let lastOutputTime = Date.now();
  
  const handleOutput = (data) => {
    const rawOutput = data.toString();
    const formattedOutput = formatOutput(data);
    if (formattedOutput) {
      console.log(formattedOutput);
    }
    lastOutputTime = Date.now();

    if (platformShutdownResolve && rawOutput.includes('Platform stopped')) {
      setTimeout(() => platformShutdownResolve(), 500);
    }
  };
  
  process.stdout.on('data', handleOutput);
  process.stderr.on('data', handleOutput);
  
  process.waitForShutdown = () => new Promise((resolve) => {
    platformShutdownResolve = resolve;
  });
  
  process.getLastOutputTime = () => lastOutputTime;
  
  process.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.log(`\n[nodemon] exited with code ${code}`);
    }
  });
}

let schemaGenTimeout = null;
let isSchemaGenerating = false;

function runGraphQLBuild() {
  // Skip if already generating
  if (isSchemaGenerating) {
    console.log('[WATCH] Schema generation already in progress, skipping...');
    return;
  }
  
  // Debounce to avoid multiple rapid runs
  if (schemaGenTimeout) {
    clearTimeout(schemaGenTimeout);
  }
  
  schemaGenTimeout = setTimeout(() => {
    console.log('[WATCH] Running GraphQL schema build...');
    isSchemaGenerating = true;
    
    try {
      const schemaProcess = spawn('yarn', ['build:schema'], {
        cwd: CONFIG.projectRoot,
        stdio: ['inherit', 'inherit', 'inherit'],
        shell: false,
        env: { ...process.env }
      });
      
      schemaProcess.on('exit', () => {
        isSchemaGenerating = false;
        console.log('[WATCH] GraphQL schema build completed');
      });
      
      schemaProcess.on('error', (err) => {
        isSchemaGenerating = false;
        console.error('[WATCH] GraphQL build failed:', err);
      });
    } catch (err) {
      isSchemaGenerating = false;
      console.error('[WATCH] GraphQL build failed:', err);
    }
  }, 500); // Wait 500ms to batch changes
}

function startNodemon() {
  console.log('Starting nodemon...\n');

  const configPath = path.join(CONFIG.projectRoot, 'nodemon.json');

  const nodemonArgs = ['--config', configPath];
  
  nodemonProcess = spawn('nodemon', nodemonArgs, {
    cwd: CONFIG.projectRoot,
    stdio: ['inherit', 'pipe', 'pipe'],
    shell: false,
    detached: false
  });
  
  setupNodemonOutputHandlers(nodemonProcess);
  
  nodemonProcess.on('error', (err) => {
    console.error('[WATCH] Failed to start nodemon:', err);
  });
}

function handleEsbuildOutput(data) {
  const output = data.toString();
  process.stdout.write(output);
  
  if (!initialBuildDone && output.includes('✅ Initial build complete')) {
    initialBuildDone = true;
    startNodemon();
  }
  if (CONFIG.graphql) {
    runGraphQLBuild();
  }
}

function startEsbuild() {
  esbuildProcess = spawn('node', ['builder/dev/dev.js', '--watch'], {
    cwd: CONFIG.projectRoot,
    stdio: 'pipe',
    shell: false,
    env: { ...process.env }
  });
  
  esbuildProcess.stdout.on('data', handleEsbuildOutput);
  esbuildProcess.stderr.on('data', (data) => process.stderr.write(data));
  
  esbuildProcess.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.log(`\n[esbuild] exited with code ${code}`);
      cleanup('esbuild exit');
    }
  });
}

function stopEsbuild() {
  if (esbuildProcess && !esbuildProcess.killed) {
    console.log('[WATCH] Stopping esbuild...');
    esbuildProcess.kill('SIGTERM');
  }
}

async function waitForNodemonShutdown() {
  const shutdownPromise = nodemonProcess.waitForShutdown();
  
  const exitPromise = new Promise((resolve) => {
    nodemonProcess.once('exit', async () => {
      await new Promise(r => setTimeout(r, CONFIG.shutdownDelay));
      resolve();
    });
  });
  
  // Always use SIGTERM - in dev mode, child lock manager exits immediately
  nodemonProcess.kill('SIGTERM');
  await Promise.race([shutdownPromise, exitPromise]);
}

function displayShutdownMessage() {
  console.log('[WATCH] OpenCTI stopped successfully.');
}

async function cleanup(signal) {
  console.log(`\n[WATCH] Received ${signal}, shutting down gracefully...`);
  
  stopEsbuild();
  
  if (nodemonProcess && !nodemonProcess.killed) {
    console.log('[WATCH] waiting for OpenCTI shutdown...');
    
    let shutdownCompleted = false;
    const shutdownTimeout = setTimeout(() => {
      if (!shutdownCompleted) {
        console.log('[WATCH] Shutdown timeout reached, forcing exit');
        process.exit(1);
      }
    }, CONFIG.shutdownTimeout);
    
    await waitForNodemonShutdown();
    
    shutdownCompleted = true;
    clearTimeout(shutdownTimeout);
    
    displayShutdownMessage();
  }
  
  process.exit(0);
}

function main() {
  displayStartupMessage();
  startEsbuild();

  process.on('SIGINT', () => cleanup('SIGINT'));
  process.on('SIGTERM', () => cleanup('SIGTERM'));
}

main();
