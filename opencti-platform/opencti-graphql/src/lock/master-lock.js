import { fork } from 'child_process';
import * as crypto from 'crypto';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import conf, { booleanConf, logApp } from '../config/conf';
import { lockResource } from '../database/redis';
import { meterManager } from '../config/tracing';

// Global variable for the child process
const USE_CHILD_LOCK = booleanConf('app:child_locking_process:enabled', false);
const CHILD_PROCESS_MEMORY = conf.get('app:child_locking_process:max_memory') ?? '256';
const lockProcess = {
  forked: undefined,
  callbacks: new Map(), // [op, { lock: fn, unlock: fn }]
};

// -- Start the control lock manager
export const initLockFork = () => {
  if (!USE_CHILD_LOCK) {
    return;
  }
  if (!lockProcess.forked) {
    lockProcess.forked = fork('./build/child-lock.manager.mjs', {
      execArgv: [`--max-old-space-size=${CHILD_PROCESS_MEMORY}`],
    }, { detached: false });
    lockProcess.forked.on('message', (msg) => {
      const messageKey = `${msg.operation}-${msg.type}`;
      if (lockProcess.callbacks.has(messageKey)) {
        lockProcess.callbacks.get(messageKey)(msg);
      } else {
        logApp.warn('[LOCKING] Locking message with invalid operation', { key: messageKey });
      }
    });
    lockProcess.forked.on('exit', (code) => {
      // If exit is detected, exit the parent process
      // It should not happen in standard situation
      process.exit(code);
    });
    logApp.info('[LOCKING] Locking fork process started');
  } else {
    logApp.info('[LOCKING] Locking fork process already started');
  }
};

// Record lock acquisition telemetry. Must run in THIS (main) process: it holds the metric exporter.
// The measurement itself is done next to the redlock acquire (redis.ts lockResource), in whichever
// process performs it (direct or lock child), and travels back with the lock/IPC message.
const recordLockAcquire = (acquireWaitMs, acquireAttempts) => {
  if (acquireWaitMs === undefined) {
    return;
  }
  meterManager.lockWait(acquireWaitMs);
  if (acquireAttempts > 1) {
    meterManager.lockContention();
  }
};

const removeAllCallbacksForOperation = (operation) => {
  lockProcess.callbacks.delete(`${operation}-lock`);
  lockProcess.callbacks.delete(`${operation}-unlock`);
  lockProcess.callbacks.delete(`${operation}-abort`);
};

// Unlock definition
const childUnlockResources = async (operation) => {
  return new Promise((resolve, reject) => {
    // Set up the unlock callback
    lockProcess.callbacks.set(`${operation}-unlock`, (msg) => {
      // Cleanup the callback map
      removeAllCallbacksForOperation(operation);
      // Resolve or reject depending on the unlock result
      if (msg.success) {
        resolve(msg);
      } else {
        reject(msg.error);
      }
    });
    // Send the unlock operation to the child process
    lockProcess.forked.send({ type: 'unlock', operation });
  });
};

// Lock resources definition
const childLockResources = async (ids, args = {}) => {
  if (!lockProcess.forked) {
    throw UnsupportedError('Lock child fork not initialize');
  }
  const operation = crypto.randomUUID(); // Use crypto to fast ramdom generation
  const controller = new AbortController();
  const { signal } = controller;
  return new Promise((resolve, reject) => {
    // Set up the abort callback
    lockProcess.callbacks.set(`${operation}-abort`, () => {
      controller.abort({ name: TYPE_LOCK_ERROR });
    });
    // Set up the lock callback
    lockProcess.callbacks.set(`${operation}-lock`, (msg) => {
      if (msg.success) {
        recordLockAcquire(msg.acquireWaitMs, msg.acquireAttempts);
        const unlock = () => childUnlockResources(msg.operation);
        resolve({ operation, signal, unlock, result: msg });
      } else {
        // Cleanup the callback map
        removeAllCallbacksForOperation(operation);
        reject(msg.error);
      }
    });
    // Send the lock operation to the child process
    lockProcess.forked.send({ type: 'lock', operation, ids, args });
  });
};

// Lock resources, direct or child, depending
export const lockResources = async (ids, args = {}) => {
  // POC ingestion sequencer (plan 0009 D4): under an applying batch, keys already held by
  // the batch lock are a no-op (re-locking them would deadlock against our own batch lock);
  // only the keys the pre-resolution could not predict take a real lock. The returned handle
  // exposes the batch lock's signal and a no-op unlock.
  const { sequencer, ...cleanArgs } = args;
  if (sequencer) {
    const missing = ids.filter((id) => !sequencer.heldKeys.has(id));
    if (missing.length === 0) {
      return { operation: 'sequencer-batch', signal: sequencer.signal, unlock: async () => {} };
    }
    return lockResources(missing, cleanArgs);
  }
  if (USE_CHILD_LOCK) {
    return childLockResources(ids, cleanArgs);
  }
  const lock = await lockResource(ids, cleanArgs);
  recordLockAcquire(lock.acquireWaitMs, lock.acquireAttempts);
  return lock;
};
