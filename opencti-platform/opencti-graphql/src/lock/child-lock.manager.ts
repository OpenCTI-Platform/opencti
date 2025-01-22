import { initializeOnlyRedisLockClient, lockResource } from '../database/redis';

interface InternalLock {
  signal: AbortSignal
  extend: () => Promise<void>
  unlock: () => Promise<void>
}

const activeLocks: Map<string, InternalLock> = new Map<string, InternalLock>();

interface LockData {
  type: 'lock' | 'unlock'
  operation: string
  ids: string[]
  args: object
}

initializeOnlyRedisLockClient().then(() => {
  // Listing on parent messaging
  process.on('message', async (data: LockData) => {
    // In case of lock
    if (data.type === 'lock') {
      try {
        const lock = await lockResource(data.ids, data.args);
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
});
