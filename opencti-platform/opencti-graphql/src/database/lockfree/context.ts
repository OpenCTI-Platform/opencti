// Shared helpers of the lock-free write path
import { executionContext } from '../../utils/access';

// Context of the path's own reads and writes (identity index, pairs, settler), not tied to a request
export const lockfreeContext = executionContext('lockfree_ingestion');

// Runs fn over items, at most `concurrency` at once
export const pool = async <T>(items: T[], concurrency: number, fn: (item: T, index: number) => Promise<void>) => {
  let next = 0;
  const runners = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      await fn(items[index], index);
    }
  });
  await Promise.all(runners);
};
