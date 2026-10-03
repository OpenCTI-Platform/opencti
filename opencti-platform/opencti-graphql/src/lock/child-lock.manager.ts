import { initializeOnlyRedisLockClient, lockResource } from '../database/redis';
import { logApp } from '../config/conf';
const PARENT_PROCESS_SCHEDULE_LISTENER = 2000;

interface InternalLock {
  signal: AbortSignal;
  extend: () => Promise<void>;
  unlock: () => Promise<void>;
  acquireWaitMs?: number;
  acquireAttempts?: number;
}

const activeLocks: Map<string, InternalLock> = new Map<string, InternalLock>();

interface LockData {
  type: 'lock' | 'unlock';
  operation: string;
  ids: string[];
  args: object;
}

initializeOnlyRedisLockClient().then(() => {
  // In development mode, release all locks and exit immediately on SIGTERM/SIGINT
  // This enables instant hot reload without lock conflicts
  const isDevelopment = process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'dev';
  let shutdownInProgress = false;

  // Listing on parent messaging
  process.on('message', async (data: LockData) => {
    // In case of lock
    if (data.type === 'lock') {
      // Reject new lock requests once shutdown has started so we don't race
      // freshly-acquired locks against the final activeLocks drain below.
      if (shutdownInProgress) {
        if (process.send) {
          process.send({ operation: data.operation, error: new Error('Child lock manager is shutting down'), type: data.type, success: false });
        }
        return;
      }
      try {
        const options = { child_operation: data.operation, ...data.args };
        const lock = await lockResource(data.ids, options);
        activeLocks.set(data.operation, lock);
        if (process.send) {
          // Ship the acquisition measures to the parent: metrics are recorded there (master-lock),
          // this child process has no metric exporter.
          process.send({
            operation: data.operation,
            type: data.type,
            success: true,
            acquireWaitMs: lock.acquireWaitMs,
            acquireAttempts: lock.acquireAttempts,
          });
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

  const quickShutdown = async () => {
    if (shutdownInProgress) {
      return;
    }
    shutdownInProgress = true;

    logApp.info(`[LOCK-MANAGER] Dev mode: releasing ${activeLocks.size} active lock(s)`);

    const deadline = Date.now() + 1000;
    // Locks whose acquisition was already in flight when shutdown started can
    // resolve and be added to activeLocks after our first pass, so keep
    // draining the map until it's empty or the time budget runs out, instead
    // of relying on a single Array.from(...) snapshot.
    const releaseAll = async () => {
      while (activeLocks.size > 0 && Date.now() < deadline) {
        const pending = Array.from(activeLocks.entries());
        await Promise.all(pending.map(async ([operation, lock]) => {
          try {
            await lock.unlock();
          } catch (err) {
            logApp.error('[LOCK-MANAGER] Error unlocking', { error: err });
          } finally {
            activeLocks.delete(operation);
          }
        }));
      }
    };

    // Wait up to 1 second for unlocks, then exit anyway
    await Promise.race([
      releaseAll(),
      new Promise((resolve) => {
        setTimeout(resolve, 1000);
      }),
    ]);

    activeLocks.clear();
    logApp.info('[LOCK-MANAGER] Dev mode: locks released, exiting');
    process.exit(0);
  };

  if (isDevelopment) {
    const handleShutdownSignal = () => {
      quickShutdown().catch(() => process.exit(0));
    };
    process.on('SIGTERM', handleShutdownSignal);
    process.on('SIGINT', handleShutdownSignal);
  } else {
    // In production, ignore signals since we're attached to parent
    const ignoreSignal = () => {};
    process.on('SIGTERM', ignoreSignal);
    process.on('SIGINT', ignoreSignal);
  }

  // Check with standard interval if the parent process is no longer running
  // If the parent is not available anymore, exit the process
  setInterval(() => {
    if (!process.ppid || process.ppid === 1) {
      process.exit(1);
    }
  }, PARENT_PROCESS_SCHEDULE_LISTENER);
}).catch((reason) => logApp.error('Child lock manager unknown error.', { cause: reason }));
