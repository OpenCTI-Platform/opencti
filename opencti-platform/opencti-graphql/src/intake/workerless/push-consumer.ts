import amqp from 'amqplib/callback_api';
import { logApp } from '../../config/conf';
import { rabbitmqConnectionOptions, rabbitmqUri } from '../../database/rabbitmq';
import { createByteBudget, createQueueOrder, handlePushMessage, isEventMessage, parsePushMessage, type PushIntakeDeps, type PushOutcome } from './push-intake';

// The broker side of the worker-less intake (POC): one connection, one channel per push queue as
// the worker has one consumer per queue, manual acks. A message is answered on the channel it came
// on, once handled (push-intake.ts); a channel closed before the answer drops it, the broker
// redelivers it. The queues are read from the connectors on each tick of the manager (refresh):
// a connector registered after the start is consumed from the next tick.

const LOG_PREFIX = '[OPENCTI-MODULE] Worker-less intake:';

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
  close: () => Promise<void>;
}

export const consumePushQueues = async (
  listQueues: () => Promise<string[]>,
  deps: PushIntakeDeps,
  options: PushConsumerOptions,
  onOutcome: (outcome: PushOutcome, queue: string) => void,
): Promise<PushConsumer> => {
  const budget = createByteBudget(options.maxInFlightBytes);
  const order = createQueueOrder();
  const consumed = new Set<string>();
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
      outcome = await handlePushMessage(data, deps);
    } catch (cause) {
      logApp.error(`${LOG_PREFIX} push message handling failed`, { queue, cause });
      outcome = { ack: false, reason: 'transformation_failed', chunks: 0, objects: 0 };
    } finally {
      budget.release(bytes);
    }
    if (open()) {
      try {
        if (outcome.ack) {
          channel.ack(message);
        } else {
          channel.nack(message, false, false);
        }
      } catch (cause) {
        logApp.warn(`${LOG_PREFIX} answer failed, the broker redelivers the message`, { queue, cause });
      }
    }
    onOutcome(outcome, queue);
  };

  const consumeQueue = (queue: string) => {
    consumed.add(queue);
    connection.createChannel((channelError, channel) => {
      if (channelError) {
        consumed.delete(queue);
        logApp.warn(`${LOG_PREFIX} cannot open a channel, queue not consumed`, { queue, cause: channelError });
        return;
      }
      let open = true;
      channel.on('error', (cause) => logApp.warn(`${LOG_PREFIX} channel error, queue no longer consumed`, { queue, cause }));
      channel.on('close', () => {
        open = false;
        consumed.delete(queue);
      });
      channel.prefetch(options.prefetch, false);
      channel.consume(queue, (message) => {
        if (message === null) {
          // Cancelled by the broker (queue deleted)
          try {
            channel.close(() => {});
          } catch {
            // Already closing
          }
          return;
        }
        // Parsed once, on delivery: its type decides the order (an event queue is consumed in order)
        const data = parsePushMessage(message.content.toString());
        order.schedule(queue, isEventMessage(data ?? {}), () => handle(queue, channel, () => open, message, data))
          .catch((cause) => logApp.error(`${LOG_PREFIX} push message scheduling failed`, { queue, cause }));
      }, { noAck: false });
    });
  };

  const refresh = async () => {
    if (!alive) return;
    const queues = await listQueues();
    queues.filter((queue) => !consumed.has(queue)).forEach(consumeQueue);
  };
  await refresh();
  logApp.info(`${LOG_PREFIX} consuming`, { queues: consumed.size, prefetch: options.prefetch, max_in_flight_bytes: options.maxInFlightBytes });
  return {
    queue: 'push queues',
    alive: () => alive,
    refresh,
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
