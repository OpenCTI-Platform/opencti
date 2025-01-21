import { fork } from 'child_process';
import * as crypto from 'crypto';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import conf, { logApp } from '../config/conf';

// Global variable for the child process
const CHILD_PROCESS_MEMORY = conf.get('app:locking_process:max_memory') ?? '256';
const lockProcess = {
  forked: undefined,
  callbacks: new Map() // [op, { lock: fn, unlock: fn }]
};

// -- Start the control lock manager
export const initLockFork = () => {
  if (!lockProcess.forked) {
    lockProcess.forked = fork('./build/child-lock.manager.js', {
      execArgv: [`--max-old-space-size=${CHILD_PROCESS_MEMORY}`]
    });
    lockProcess.forked.on('message', (msg) => {
      const messageKey = `${msg.operation}-${msg.type}`;
      if (lockProcess.callbacks.has(messageKey)) {
        lockProcess.callbacks.get(messageKey)(msg);
      } else {
        logApp.warn('[LOCKING] Locking message with invalid operation', { operation: msg.operation });
      }
    });
    logApp.info('[LOCKING] Locking fork process started');
  } else {
    logApp.info('[LOCKING] Locking fork process already started');
  }
};

// Unlock definition
const unlockResources = async (operation) => {
  return new Promise((resolve, reject) => {
    // Set up the unlock callback
    lockProcess.callbacks.set(`${operation}-unlock`, (msg) => {
      // Cleanup the callback map
      lockProcess.callbacks.delete(`${operation}-lock`);
      lockProcess.callbacks.delete(`${operation}-unlock`);
      lockProcess.callbacks.delete(`${operation}-abort`);
      // Resolve or reject depending on the unlock result
      if (msg.success) {
        resolve(msg);
      } else {
        reject(msg.error);
      }
    });
    // Send the unlock operation to the child process
    lockProcess.forked.send({ type: 'unlock', operation },);
  });
};

// Lock resources definition
export const lockResources = async (ids, args = {}) => {
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
        resolve({
          operation,
          signal,
          unlock: () => unlockResources(msg.operation),
          result: msg
        });
      } else {
        reject(msg.error);
      }
    });
    // Send the lock operation to the child process
    lockProcess.forked.send({ type: 'lock', operation, ids, args });
  });
};
