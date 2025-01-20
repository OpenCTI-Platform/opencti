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
}

redisInit().then(() => {
  process.on('message', async (data: LockData) => {
    console.log('> child message', data);
    if (data.type === 'lock') {
      try {
        const lock = await lockResource(data.ids);
        activeLocks.set(data.operation, lock);
        if (process.send) {
          process.send({ operation: data.operation, type: data.type, success: true });
        }
      } catch (err) {
        console.log('> child err', err);
        if (process.send) {
          process.send({ operation: data.operation, error: err, type: data.type, success: false });
        }
      }
    }
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
        }
      }
    }
  });
});
