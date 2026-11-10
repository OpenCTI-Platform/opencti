import { performance } from 'node:perf_hooks';
import { setImmediate as setImmediateAsync } from 'node:timers/promises';

const MAX_EVENT_LOOP_PROCESSING_TIME = 50;

let nextYield: number | undefined;
// Synchronous half of doYield: true when the caller must yield now. Lets hot loops skip the
// promise of an awaited doYield() when there is nothing to yield (the common case).
export const shouldYield = (): boolean => {
  const now = performance.now();
  if (nextYield !== undefined) {
    if (now > nextYield) {
      nextYield = undefined;
      return true;
    }
  } else {
    nextYield = now + MAX_EVENT_LOOP_PROCESSING_TIME;
  }
  return false;
};
export const yieldNow = (): Promise<void> => setImmediateAsync();
export const doYield = async (): Promise<boolean> => {
  if (shouldYield()) {
    await yieldNow();
    return true;
  }
  return false;
};
