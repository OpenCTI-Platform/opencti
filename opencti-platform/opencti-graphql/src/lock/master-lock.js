import { fork } from 'child_process';
import { v4 as uuidv4 } from 'uuid';
import { TYPE_LOCK_ERROR, UnsupportedError } from '../config/errors';
import { logApp } from '../config/conf';

// -- Start the control lock manager
let forked;
export const initLockFork = () => {
  if (!forked) {
    forked = fork('./build/child-lock.manager.js');
    logApp.info('[CHECK] Locking fork process started');
  } else {
    logApp.info('[CHECK] Locking fork process already started');
  }
};

const unlockResources = async (operation) => {
  return new Promise((resolve, reject) => {
    forked.send({ type: 'unlock', operation },);
    forked.on('message', (msg) => {
      if (msg.operation === operation && msg.type === 'unlock') {
        if (msg.success) {
          resolve(msg);
        } else {
          reject(msg.error);
        }
      }
    });
  });
};
export const lockResources = async (ids, args = {}) => {
  if (!forked) {
    throw UnsupportedError('Lock child fork not initialize');
  }
  const operation = uuidv4();
  const controller = new AbortController();
  const { signal } = controller;
  return new Promise((resolve, reject) => {
    forked.send({ type: 'lock', operation, ids, args });
    forked.on('message', (msg) => {
      if (msg.operation === operation && msg.type === 'lock') {
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
      }
      if (msg.operation === operation && msg.operation === 'abort') {
        controller.abort({ name: TYPE_LOCK_ERROR });
      }
    });
  });
};
