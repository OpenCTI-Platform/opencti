import { lockResource, redisInit } from '../database/redis';

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

redisInit().then(() => {
  process.on('message', async (data: LockData) => {
    if (data.type === 'lock') {
      // console.log('> locking', data.operation, data.ids);
      try {
        const lock = await lockResource(data.ids, data.args);
        activeLocks.set(data.operation, lock);
        if (process.send) {
          process.send({ operation: data.operation, type: data.type, success: true });
        }
      } catch (err) {
        // console.log('> child err', err);
        if (process.send) {
          process.send({ operation: data.operation, error: err, type: data.type, success: false });
        }
      }
    }
    if (data.type === 'unlock') {
      const currentLock = activeLocks.get(data.operation);
      if (currentLock) {
        // console.log('> unlocking', data.operation);
        try {
          await currentLock.unlock();
          if (process.send) {
            process.send({ operation: data.operation, type: data.type, success: true });
          }
        } catch (err) {
          if (process.send) {
            process.send({ operation: data.operation, error: err, type: data.type, success: false });
          }
        }
      }
    }
  });
});
