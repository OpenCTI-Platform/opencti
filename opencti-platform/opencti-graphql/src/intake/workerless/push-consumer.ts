import amqp from 'amqplib/callback_api';
import { logApp } from '../../config/conf';
import { rabbitmqConnectionOptions, rabbitmqUri } from '../../database/rabbitmq';
import { createByteBudget, createQueueOrder, handlePushMessage, isEventMessage, parsePushMessage, type PushIntakeDeps, type PushOutcome } from './push-intake';

// The broker side of the worker-less intake (POC): one connection, one channel per push queue as
// the worker has one consumer per queue, manual acks. A message is answered on the channel it came
// on, once handled (push-intake.ts); a channel closed before the answer drops it, the broker
// redelivers it. The queues are read from the connectors on each tick of the manager (refresh):
// a connector registered after the start is consumed from the next tick, a queue no longer listed
// is stopped (its consumer cancelled, its messages in flight answered, then its channel closed).

const LOG_PREFIX = '[OPENCTI-MODULE] Worker-less intake:';
const REQUEUE_DELAY_MS = 2000;

export interface PushConsumerOptions {
  // Unacked messages per queue
  prefetch: number;
  // Bytes of the messages in flight
  maxInFlightBytes: number;
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
}

export const consumePushQueues = async (
  listQueues: () => Promise<string[]>,
  deps: PushIntakeDeps,
  options: PushConsumerOptions,
  onOutcome: (outcome: PushOutcome, queue: string) => void,
): Promise<PushConsumer> => {
  const budget = createByteBudget(options.maxInFlightBytes);
  const order = createQueueOrder();
  const consumed = new Map<string, ConsumedQueue>();
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

  const consumeQueue = (queue: string) => {
    const entry: ConsumedQueue = { channel: null, consumerTag: null, inFlight: 0, stopping: false };
    consumed.set(queue, entry);
    connection.createChannel((channelError, channel) => {
      if (channelError) {
        consumed.delete(queue);
        logApp.warn(`${LOG_PREFIX} cannot open a channel, queue not consumed`, { queue, cause: channelError });
        return;
      }
      let open = true;
      entry.channel = channel;
      channel.on('error', (cause) => logApp.warn(`${LOG_PREFIX} channel error, queue no longer consumed`, { queue, cause }));
      channel.on('close', () => {
        open = false;
        if (consumed.get(queue) === entry) consumed.delete(queue);
      });
      channel.prefetch(options.prefetch, false);
      channel.consume(queue, (message) => {
        if (message === null) {
          // Cancelled by the broker (queue deleted)
          closeChannel(channel);
          return;
        }
        // Parsed once, on delivery: its type decides the order (an event queue is consumed in order);
        // from the raw bytes, its base64 content sliced out (not decoded here)
        const data = parsePushMessage(message.content);
        entry.inFlight += 1;
        order.schedule(queue, isEventMessage(data ?? {}), () => handle(queue, channel, () => open, message, data))
          .catch((cause) => logApp.error(`${LOG_PREFIX} push message scheduling failed`, { queue, cause }))
          .finally(() => answered(entry));
      }, { noAck: false }, (consumeError, ok) => {
        if (consumeError) return; // the channel is closed with the error
        entry.consumerTag = ok.consumerTag;
        if (entry.stopping) stopQueue(entry);
      });
    });
  };

  // A stopping queue is consumed again once its channel is closed (next refresh)
  const refresh = async () => {
    if (!alive) return;
    const queues = new Set(await listQueues());
    [...queues].filter((queue) => !consumed.has(queue)).forEach(consumeQueue);
    [...consumed].filter(([queue, entry]) => !queues.has(queue) && !entry.stopping).forEach(([, entry]) => stopQueue(entry));
  };
  await refresh();
  logApp.info(`${LOG_PREFIX} consuming`, { queues: consumed.size, prefetch: options.prefetch, max_in_flight_bytes: options.maxInFlightBytes });
  return {
    queue: 'push queues',
    alive: () => alive,
    refresh,
    isOrdered: (queue) => order.isOrdered(queue),
    isConsuming: (queue) => consumed.has(queue),
    close: async () => {
      alive = false;
      try {
        connection.close();
      } catch {
        // Already closed
      }
    },
  };
};
