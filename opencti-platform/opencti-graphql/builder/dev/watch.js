#!/usr/bin/env node

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const CONFIG = {
  quickShutdown: process.argv.includes('--quick-shutdown'),
  projectRoot: path.resolve(__dirname, '..', '..'),
  shutdownTimeout: 35000,
  quickShutdownDelay: 1000,
  safeShutdownQuietTime: 30000,
  quickRestartDelay: 500,
  safeRestartDelay: 2000
};

let initialBuildDone = false;
let nodemonProcess = null;
let esbuildProcess = null;

function displayStartupMessage() {
  if (CONFIG.quickShutdown) {
    console.log('🚀 Starting dev OpenCTI with hot reload (quick shutdown)...\n');
  } else {
    console.log('🚀 Starting dev OpenCTI with hot reload (safe shutdown)...\n');
  }
}

function createQuickModeConfig() {
  const nodemonConfigPath = path.join(CONFIG.projectRoot, 'nodemon-quick.json');
  const baseConfig = JSON.parse(
    fs.readFileSync(path.join(CONFIG.projectRoot, 'nodemon.json'), 'utf8')
  );
  
  const quickConfig = {
    ...baseConfig,
    signal: 'SIGKILL', // Force kill, no graceful shutdown
    delay: CONFIG.quickRestartDelay
  };
  
  fs.writeFileSync(nodemonConfigPath, JSON.stringify(quickConfig, null, 2));
  console.log('[WATCH] Using quick restart mode (SIGKILL)\n');
  
  return nodemonConfigPath;
}

function setupNodemonOutputHandlers(process) {
  let platformShutdownResolve = null;
  let lastOutputTime = Date.now();
  
  const handleOutput = (data) => {
    const output = data.toString();
    // Write directly to stdout/stderr to ensure logs are visible
    console.log(output.trimEnd());
    lastOutputTime = Date.now();
    
    if (platformShutdownResolve && output.includes('Platform stopped')) {
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

function startNodemon() {
  console.log('Starting nodemon...\n');
  
  const configPath = CONFIG.quickShutdown 
    ? createQuickModeConfig()
    : path.join(CONFIG.projectRoot, 'nodemon.json');
  
  const nodemonArgs = ['--config', configPath, 'build/back.js'];
  
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

async function waitForLogsToStop() {
  console.log('[WATCH] Waiting for all shutdown logs to complete (safe mode)...');
  
  while (true) {
    const timeSinceLastOutput = Date.now() - nodemonProcess.getLastOutputTime();
    if (timeSinceLastOutput >= CONFIG.safeShutdownQuietTime) {
      break;
    }
    await new Promise(r => setTimeout(r, 500));
  }
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
      if (CONFIG.quickShutdown) {
        console.log('[WATCH] Quick shutdown - background cleanup may still be running...');
        await new Promise(r => setTimeout(r, CONFIG.quickShutdownDelay));
      } else {
        await waitForLogsToStop();
      }
      resolve();
    });
  });
  
  nodemonProcess.kill('SIGTERM');
  await Promise.race([shutdownPromise, exitPromise]);
}

// Display shutdown completion message
function displayShutdownMessage() {
  if (CONFIG.quickShutdown) {
    console.log('[WATCH] OpenCTI process terminated');
    console.log('[WATCH] Note: processes may still be cleaning up in the background');
  } else {
    console.log('[WATCH] OpenCTI stopped successfully');
  }
}

// Main cleanup handler
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

// Main entry point
function main() {
  displayStartupMessage();
  startEsbuild();
  
  // Handle Ctrl+C and other signals
  process.on('SIGINT', () => cleanup('SIGINT'));
  process.on('SIGTERM', () => cleanup('SIGTERM'));
}

// Start the watch process
main();
