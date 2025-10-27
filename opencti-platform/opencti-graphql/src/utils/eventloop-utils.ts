import { performance } from 'node:perf_hooks';
import { setImmediate as setImmediateAsync } from 'node:timers/promises';

const MAX_EVENT_LOOP_PROCESSING_TIME = 50;

let nextYield: number | undefined;
export const doYield = async (): Promise<boolean> => {
  const now = performance.now();
  if (nextYield !== undefined) {
    if (now > nextYield) {
      nextYield = undefined;
      await setImmediateAsync();
      return true;
    }
  } else {
    nextYield = now + MAX_EVENT_LOOP_PROCESSING_TIME;
  }
  return false;
};
