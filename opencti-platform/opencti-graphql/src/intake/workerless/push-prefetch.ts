// task 0040 prefetch by bytes: RabbitMQ bounds a consumer by messages only (basic.qos prefetch-size is not
// implemented, global qos is denied by default since RabbitMQ 4), and the messages of a queue range from a few
// KB (one object per message, split by the connector) to hundreds of MB (a whole bundle). A fixed count either
// starves the batches when few queues are active (misp split by the connector: 8.8 operations per batch at 25,
// 194 at 600) or holds GBs of giant messages. The platform shares two budgets between the queues it consumes:
// the messages that fill the sequencer batches, and the bytes it holds delivered. With 20 or 30 active queues
// a queue gets about what the fixed 25 gave; alone, it gets up to the bound.
//
// What it holds: the active queues within the budgets, each up to 4/3 of its plan (a prefetch is lowered once
// a quarter above it); the idle ones up to the start value each; a queue always takes one message, so giants
// hold one message per queue whatever the byte budget. Outside the plan: during a change the old consumer's
// messages (push-consumer.ts), and what the broker delivers under a credit before the first large message
// lowers it: raises are planned per tick, at most x2, from sizes seen recently, so that a queue known to carry
// large messages is not raised to the bound at once.

// RabbitMQ encodes the prefetch count on 16 bits, and 0 means unlimited
export const PREFETCH_LIMIT = 65535;

export interface PushPrefetchOptions {
  // Before anything is known of a queue, and the most an ordered (event) queue holds, which runs one message at
  // a time: more would only hold memory and widen the window a requeued event can be overtaken in
  initial: number;
  // Shared between the active queues; 0 for either keeps every queue at `initial`
  totalBytes: number;
  totalMessages: number;
  // Bound of one queue
  max: number;
}

export interface QueuePrefetchInput {
  queue: string;
  // Messages ready or in flight recently (push-consumer.ts holds the state a few ticks)
  active: boolean;
  // Mean size of the messages ready in the broker (management stats, sampled; 0 when unknown)
  meanReadyBytes: number;
  // Largest message delivered here recently (local, decaying)
  largestRecentBytes: number;
  ordered: boolean;
}

const bound = (value: number, max: number): number => {
  const limit = Math.min(Math.max(1, Math.floor(max) || 1), PREFETCH_LIMIT);
  return Number.isFinite(value) ? Math.max(1, Math.min(limit, Math.floor(value))) : 1;
};

export const initialPrefetch = (options: PushPrefetchOptions): number => bound(options.initial, options.max);

// The prefetch of one queue, its share taken among `shares` queues
export const prefetchFor = (input: QueuePrefetchInput, shares: number, options: PushPrefetchOptions): number => {
  const initial = initialPrefetch(options);
  if (input.ordered || !(options.totalBytes > 0) || !(options.totalMessages > 0)) return initial;
  const size = Math.max(input.meanReadyBytes || 0, input.largestRecentBytes || 0);
  // A queue whose message size is unknown is not raised: the next messages could be giants
  if (!(size > 0)) return initial;
  const n = Math.max(1, shares);
  const target = bound(Math.min(options.totalMessages / n, options.totalBytes / n / size), options.max);
  // A queue with nothing to do is sized for the whole set of queues, not for the active ones only: a burst on
  // every idle queue at once stays within the message budget
  return input.active ? target : Math.min(initial, target);
};

// The prefetch of every queue consumed here and the queues each shares the budgets with: the active ones
// share them, the idle ones take their part of the whole set
export const planPrefetch = (inputs: QueuePrefetchInput[], options: PushPrefetchOptions): Map<string, { prefetch: number; shares: number }> => {
  const active = inputs.filter((input) => input.active).length;
  return new Map(inputs.map((input) => {
    const shares = input.active ? active : inputs.length;
    return [input.queue, { prefetch: prefetchFor(input, shares, options), shares }];
  }));
};

// An ordered or idle queue is held up to the start value (prefetchFor)
export const heldToStart = (input: QueuePrefetchInput): boolean => input.ordered || !input.active;

// The new prefetch, or null to keep the current one (each change re-creates the consumer): lowered when the
// plan is under 3/4 of it, or at once for a queue held to the start value and above it; raised when the plan is
// a quarter and at least 2 above it (no 2 <-> 3 swing on giant messages), at most x2 at a time
export const nextPrefetch = (current: number, planned: number, initial: number, held = false): number | null => {
  if (planned < current) return 4 * planned < 3 * current || (held && current > initial) ? planned : null;
  const raised = Math.min(planned, 2 * current);
  return 4 * raised >= 5 * current && planned >= current + 2 ? raised : null;
};
