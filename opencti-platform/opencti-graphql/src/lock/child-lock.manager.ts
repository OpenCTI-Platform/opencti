import { initializeOnlyRedisLockClient, lockResource } from '../database/redis';
import { logApp } from '../config/conf';
const PARENT_PROCESS_SCHEDULE_LISTENER = 2000;

interface InternalLock {
  signal: AbortSignal;
  extend: () => Promise<void>;
  unlock: () => Promise<void>;
}

const activeLocks: Map<string, InternalLock> = new Map<string, InternalLock>();

interface LockData {
  type: 'lock' | 'unlock';
  operation: string;
  ids: string[];
  args: object;
}

initializeOnlyRedisLockClient().then(() => {
  // Listing on parent messaging
  process.on('message', async (data: LockData) => {
    // In case of lock
    if (data.type === 'lock') {
      try {
        const options = { child_operation: data.operation, ...data.args };
        const lock = await lockResource(data.ids, options);
        activeLocks.set(data.operation, lock);
        if (process.send) {
          process.send({ operation: data.operation, type: data.type, success: true });
        }
      } catch (err) {
        if (process.send) {
          process.send({ operation: data.operation, error: err, type: data.type, success: false });
        }
      }
    }
    // In case of unlock
    if (data.type === 'unlock') {
      const currentLock = activeLocks.get(data.operation);
      if (currentLock) {
        try {
          await currentLock.unlock();
          if (process.send) {
            process.send({ operation: data.operation, type: data.type, success: true });
          }
        } catch (err) {
          if (process.send) {
            process.send({ operation: data.operation, error: err, type: data.type, success: false });
          }
        } finally {
          activeLocks.delete(data.operation);
        }
      }
    }
  });
  // Don't do anything in exist event, process is attached to the parent
  process.on('exit', () => {});

  // In development mode, release all locks and exit immediately on SIGTERM/SIGINT
  // This enables instant hot reload without lock conflicts
  const isDevelopment = process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'dev';

  const quickShutdown = async () => {
    logApp.info(`[LOCK-MANAGER] Dev mode: releasing ${activeLocks.size} active lock(s)`);

    // Release all active locks quickly
    const unlockPromises = Array.from(activeLocks.values()).map((lock) => lock.unlock().catch((err) => logApp.error('[LOCK-MANAGER] Error unlocking', { error: err })));

    // Wait up to 1 second for unlocks, then exit anyway
    await Promise.race([
      Promise.all(unlockPromises),
      new Promise((resolve) => {
        setTimeout(resolve, 1000);
      }),
    ]);

    activeLocks.clear();
    logApp.info('[LOCK-MANAGER] Dev mode: locks released, exiting');
    process.exit(0);
  };

  if (isDevelopment) {
    process.on('SIGTERM', () => {
      quickShutdown().catch(() => process.exit(0));
    });
    process.on('SIGINT', () => {
      quickShutdown().catch(() => process.exit(0));
    });
  } else {
    // In production, ignore signals since we're attached to parent
  process.on('SIGTERM', () => {});
  process.on('SIGINT', () => {});
  }

  // Check with standard interval if the parent process is no longer running
  // If the parent is not available anymore, exit the process
  setInterval(() => {
    if (!process.ppid || process.ppid === 1) {
      process.exit(1);
    }
  }, PARENT_PROCESS_SCHEDULE_LISTENER);
}).catch((reason) => logApp.error('Child lock manager unknown error.', { cause: reason }));
