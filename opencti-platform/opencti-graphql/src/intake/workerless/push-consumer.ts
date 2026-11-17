import amqp from 'amqplib/callback_api';
import { logApp } from '../../config/conf';
import { rabbitmqConnectionOptions, rabbitmqUri } from '../../database/rabbitmq';
import { createByteBudget, createQueueOrder, handlePushMessage, isEventMessage, parsePushMessage, type PushIntakeDeps, type PushOutcome } from './push-intake';
import { isOversized, retargetPrefetch } from './push-prefetch';

// The broker side of the worker-less intake (POC): one connection, one channel per push queue as
// the worker has one consumer per queue, manual acks. A message is answered on the channel it came
// on, once handled (push-intake.ts); a channel closed before the answer drops it, the broker
// redelivers it. The queues are read from the connectors on each tick of the manager (refresh):
// a connector registered after the start is consumed from the next tick, a queue no longer listed
// is stopped (its consumer cancelled, its messages in flight answered, then its channel closed).

const LOG_PREFIX = '[OPENCTI-MODULE] Worker-less intake:';
const REQUEUE_DELAY_MS = 2000;
// task 0040: a close lets the messages in flight be answered first (a message closed unanswered is
// redelivered, possibly to another platform, while its chunks still commit here), up to this bound. At a
// platform stop the caches no longer receive invalidations during the drain, and an orchestrator grace
// period shorter than the bound (Kubernetes: 30 s) kills it midway: those messages are redelivered as before.
const CLOSE_DRAIN_MAX_MS = 60000;
const CLOSE_DRAIN_POLL_MS = 100;

// Waits until nothing is pending or maxMs elapsed; true when drained
export const waitDrained = async (pending: () => number, maxMs: number, pollMs: number, now: () => number = Date.now): Promise<boolean> => {
  const start = now();
  while (pending() > 0 && now() - start < maxMs) {
    await new Promise((resolve) => {
      setTimeout(resolve, pollMs);
    });
  }
  return pending() === 0;
};

export interface QueueSize {
  ready: number;
  bytesReady: number;
}

export interface PushConsumerOptions {
  // Unacked messages per queue, until the size of its messages is known (push-prefetch.ts)
  prefetch: number;
  // Delivered bytes held per queue (0: the prefetch stays fixed) and the prefetch bound
  prefetchBytes: number;
  maxPrefetch: number;
  // Bytes of the messages in flight
  maxInFlightBytes: number;
  // The messages ready of each queue and their bytes, read on each refresh to set its prefetch
  readSizes?: () => Promise<Map<string, QueueSize>>;
}

export interface PushConsumer {
  queue: string;
  alive: () => boolean;
  refresh: () => Promise<void>;
  isOrdered: (queue: string) => boolean;
  isConsuming: (queue: string) => boolean;
  close: () => Promise<void>;
}

interface ConsumedQueue {
  channel: amqp.Channel | null;
  consumerTag: string | null;
  inFlight: number;
  stopping: boolean;
  open: boolean;
  prefetch: number;
  retargeting: boolean;
}

export const consumePushQueues = async (
  listQueues: () => Promise<string[]>,
  deps: PushIntakeDeps,
  options: PushConsumerOptions,
  onOutcome: (outcome: PushOutcome, queue: string) => void,
  // task 0040 queue lease: told on the first event message of a queue, before it is handled, so that no
  // other platform joins a queue consumed in order (queue-lease.ts)
  onOrdered: (queue: string) => void = () => {},
): Promise<PushConsumer> => {
  const budget = createByteBudget(options.maxInFlightBytes);
  const prefetchOptions = { initial: options.prefetch, bytes: options.prefetchBytes, max: options.maxPrefetch };
  const order = createQueueOrder();
  const consumed = new Map<string, ConsumedQueue>();
  const toldOrdered = new Set<string>();
  let alive = true;
  const connection = await new Promise<amqp.Connection>((resolve, reject) => {
    amqp.connect(rabbitmqUri(), rabbitmqConnectionOptions(), (err, opened) => (err ? reject(err) : resolve(opened)));
  });
  connection.on('error', (cause) => {
    alive = false;
    logApp.error(`${LOG_PREFIX} connection error`, { cause });
  });
  connection.on('close', () => {
    alive = false;
    logApp.warn(`${LOG_PREFIX} connection closed`);
  });

  const handle = async (queue: string, channel: amqp.Channel, open: () => boolean, message: amqp.Message, data: Record<string, any> | null) => {
    const bytes = message.content.length;
    await budget.acquire(bytes);
    let outcome: PushOutcome;
    try {
      outcome = await handlePushMessage(data, queue, deps);
    } catch (cause) {
      logApp.error(`${LOG_PREFIX} push message handling failed`, { queue, cause });
      outcome = { ack: false, reason: 'transformation_failed', operations: 0, objects: 0 };
    } finally {
      budget.release(bytes);
    }
    if (outcome.requeue) {
      // given back after a pause: a classic queue redelivers it at once, and the engine needs time
      await new Promise((resolve) => {
        setTimeout(resolve, REQUEUE_DELAY_MS);
      });
    }
    if (open()) {
      try {
        if (outcome.ack) {
          channel.ack(message);
        } else {
          channel.nack(message, false, !!outcome.requeue);
        }
      } catch (cause) {
        logApp.warn(`${LOG_PREFIX} answer failed, the broker redelivers the message`, { queue, cause });
      }
    }
    onOutcome(outcome, queue);
  };

  const closeChannel = (channel: amqp.Channel) => {
    try {
      channel.close(() => {});
    } catch {
      // Already closing
    }
  };
  // Cancelled first, so the broker delivers no more; closed once the messages in flight are answered
  const stopQueue = (entry: ConsumedQueue) => {
    entry.stopping = true;
    const { channel, consumerTag } = entry;
    if (!channel || !consumerTag) return; // not consuming yet: stopped once its consumer is registered
    try {
      channel.cancel(consumerTag, (cancelError) => {
        if (cancelError || entry.inFlight === 0) closeChannel(channel);
      });
    } catch {
      // Already closing
    }
  };
  const answered = (entry: ConsumedQueue) => {
    entry.inFlight -= 1;
    if (entry.stopping && entry.inFlight === 0 && entry.channel) closeChannel(entry.channel);
  };

  // The consumer of a queue on its channel, with the entry's prefetch: RabbitMQ binds a prefetch to a consumer
  // when it is created (basic.qos, not global), a new prefetch is a new consumer on the same channel
  const startConsumer = (queue: string, entry: ConsumedQueue, channel: amqp.Channel) => {
    channel.prefetch(entry.prefetch, false);
    channel.consume(queue, (message) => {
      if (message === null) {
        // Cancelled by the broker (queue deleted)
        closeChannel(channel);
        return;
      }
      // Parsed once, on delivery: its type decides the order (an event queue is consumed in order);
      // from the raw bytes, its base64 content sliced out (not decoded here)
      const data = parsePushMessage(message.content);
      const isEvent = isEventMessage(data ?? {});
      if (isEvent && !toldOrdered.has(queue)) {
        toldOrdered.add(queue);
        onOrdered(queue);
      }
      if (isOversized(message.content.length, entry.prefetch, prefetchOptions)) {
        setPrefetch(queue, entry, retargetPrefetch(entry.prefetch, message.content.length, prefetchOptions));
      }
      entry.inFlight += 1;
      order.schedule(queue, isEvent, () => handle(queue, channel, () => entry.open, message, data))
        .catch((cause) => logApp.error(`${LOG_PREFIX} push message scheduling failed`, { queue, cause }))
        .finally(() => answered(entry));
    }, { noAck: false }, (consumeError, ok) => {
      entry.retargeting = false;
      if (consumeError) return; // the channel is closed with the error
      entry.consumerTag = ok.consumerTag;
      if (entry.stopping) stopQueue(entry);
    });
  };

  // Its consumer cancelled then created again with the new prefetch; the messages in flight stay unacked on the
  // channel and are answered on it, nothing is redelivered
  const setPrefetch = (queue: string, entry: ConsumedQueue, prefetch: number | null) => {
    const { channel, consumerTag } = entry;
    if (prefetch === null || entry.stopping || entry.retargeting || !channel || !consumerTag) return;
    logApp.info(`${LOG_PREFIX} prefetch changed`, { queue, from: entry.prefetch, to: prefetch });
    entry.retargeting = true;
    entry.consumerTag = null;
    entry.prefetch = prefetch;
    try {
      channel.cancel(consumerTag, (cancelError) => {
        if (cancelError) {
          entry.retargeting = false;
          return; // the channel is closed with the error
        }
        if (entry.stopping) {
          // stopped meanwhile: no new consumer, closed once its messages in flight are answered
          entry.retargeting = false;
          if (entry.inFlight === 0) closeChannel(channel);
          return;
        }
        startConsumer(queue, entry, channel);
      });
    } catch {
      entry.retargeting = false; // Already closing
    }
  };

  const consumeQueue = (queue: string) => {
    const entry: ConsumedQueue = { channel: null, consumerTag: null, inFlight: 0, stopping: false, open: false, prefetch: options.prefetch, retargeting: false };
    consumed.set(queue, entry);
    connection.createChannel((channelError, channel) => {
      if (channelError) {
        consumed.delete(queue);
        logApp.warn(`${LOG_PREFIX} cannot open a channel, queue not consumed`, { queue, cause: channelError });
        return;
      }
      entry.open = true;
      entry.channel = channel;
      channel.on('error', (cause) => logApp.warn(`${LOG_PREFIX} channel error, queue no longer consumed`, { queue, cause }));
      channel.on('close', () => {
        entry.open = false;
        if (consumed.get(queue) === entry) consumed.delete(queue);
      });
      startConsumer(queue, entry, channel);
    });
  };

  // A stopping queue is consumed again once its channel is closed (next refresh). A queue no longer listed
  // is stopped and drained on a single writer too (connector removed), not only when a lease moves.
  const refresh = async () => {
    if (!alive) return;
    const queues = new Set(await listQueues());
    [...queues].filter((queue) => !consumed.has(queue)).forEach(consumeQueue);
    [...consumed].filter(([queue, entry]) => !queues.has(queue) && !entry.stopping).forEach(([, entry]) => stopQueue(entry));
    if (options.prefetchBytes > 0 && options.readSizes) {
      let sizes: Map<string, QueueSize>;
      try {
        sizes = await options.readSizes();
      } catch (cause) {
        logApp.warn(`${LOG_PREFIX} queue sizes not read, prefetch kept`, { cause });
        return;
      }
      consumed.forEach((entry, queue) => {
        const size = sizes.get(queue);
        if (size && size.ready > 0) setPrefetch(queue, entry, retargetPrefetch(entry.prefetch, size.bytesReady / size.ready, prefetchOptions));
      });
    }
  };
  try {
    await refresh();
  } catch (cause) {
    // the first listing failed: nothing consumed yet, the connection is closed with it
    alive = false;
    try {
      connection.close();
    } catch {
      // Already closed
    }
    throw cause;
  }
  logApp.info(`${LOG_PREFIX} consuming`, { queues: consumed.size, prefetch: options.prefetch, prefetch_bytes: options.prefetchBytes, max_prefetch: options.maxPrefetch, max_in_flight_bytes: options.maxInFlightBytes });
  return {
    queue: 'push queues',
    alive: () => alive,
    refresh,
    isOrdered: (queue) => order.isOrdered(queue),
    isConsuming: (queue) => consumed.has(queue),
    close: async () => {
      alive = false;
      [...consumed.values()].filter((entry) => !entry.stopping).forEach(stopQueue);
      if (!await waitDrained(() => consumed.size, CLOSE_DRAIN_MAX_MS, CLOSE_DRAIN_POLL_MS)) {
        logApp.warn(`${LOG_PREFIX} closed with messages still in flight, the broker redelivers them`, { queues: consumed.size });
      }
      try {
        connection.close();
      } catch {
        // Already closed
      }
    },
  };
};
