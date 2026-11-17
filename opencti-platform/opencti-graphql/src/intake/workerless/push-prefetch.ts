// task 0040 prefetch by bytes: RabbitMQ bounds a consumer by messages only (basic.qos prefetch-size is not
// implemented), and the messages of a queue range from a few KB (one object per message, split by the
// connector) to hundreds of MB (a whole bundle). A fixed count either starves the batches on small messages
// (misp split by the connector: 8.8 operations per batch at 25, 194 at 600) or holds GBs of giant ones. The
// prefetch of each queue is set from the mean size of its ready messages, so that it holds about `bytes`.

export interface PushPrefetchOptions {
  // Before the size of the queue's messages is known
  initial: number;
  // Delivered bytes held per queue; 0 keeps the initial prefetch (count only)
  bytes: number;
  max: number;
}

export const prefetchForSize = (meanBytes: number, options: PushPrefetchOptions): number => {
  return Math.max(1, Math.min(options.max, Math.floor(options.bytes / Math.max(1, meanBytes))));
};

// The new prefetch, or null to keep the current one: changed only when off by a factor 2 or more, each change
// re-creates the consumer
export const retargetPrefetch = (current: number, meanBytes: number, options: PushPrefetchOptions): number | null => {
  if (options.bytes <= 0 || !(meanBytes > 0)) return null;
  const target = prefetchForSize(meanBytes, options);
  return target >= 2 * current || 2 * target <= current ? target : null;
};

// A delivered message that the current credit could not hold twice over within the budget: the prefetch is
// lowered at once, not at the next tick (the mean of the ready messages hides a giant one among small ones)
export const isOversized = (bytes: number, current: number, options: PushPrefetchOptions): boolean => {
  return options.bytes > 0 && bytes * current > 2 * options.bytes;
};
