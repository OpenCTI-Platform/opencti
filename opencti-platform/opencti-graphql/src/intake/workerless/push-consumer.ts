import amqp from 'amqplib/callback_api';
import { logApp } from '../../config/conf';
import { rabbitmqConnectionOptions, rabbitmqUri } from '../../database/rabbitmq';
import { createByteBudget, createQueueOrder, handlePushMessage, isEventMessage, parsePushMessage, type PushIntakeDeps, type PushOutcome, stoppedOutcome } from './push-intake';
import { heldToStart, initialPrefetch, nextPrefetch, planPrefetch, prefetchFor, type QueuePrefetchInput } from './push-prefetch';

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
// task 0040 prefetch by bytes: the largest message delivered on a queue is kept, halved every
// LARGEST_HALF_LIFE_TICKS ticks, so that a queue known to carry large messages is raised back slowly after one;
// a queue stays active (sharing the budgets) ACTIVE_HOLD_TICKS ticks after its last message, so that a queue
// trickling messages does not change every share at each tick
const LARGEST_HALF_LIFE_TICKS = 6;
const LARGEST_DECAY = 0.5 ** (1 / LARGEST_HALF_LIFE_TICKS);
// forgotten after this many ticks with nothing ready nor in flight: a long calm queue is of unknown size again
const LARGEST_FORGET_IDLE_TICKS = 10 * LARGEST_HALF_LIFE_TICKS;
const ACTIVE_HOLD_TICKS = 3;

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
  // Unacked messages per queue at start, and the fixed value of an ordered queue (push-prefetch.ts)
  prefetch: number;
  // Shared between the queues consumed here: bytes held delivered and messages delivered (0 for either: the
  // prefetch stays fixed), and the bound of one queue
  prefetchTotalBytes: number;
  prefetchTotalMessages: number;
  maxPrefetch: number;
  // Bytes of the messages in flight
  maxInFlightBytes: number;
  // The messages ready of each queue and their bytes, read on each refresh to plan the prefetches
  readSizes?: () => Promise<Map<string, QueueSize>>;
  // The queues known to be consumed in order before their first event (the synchronizations')
  isOrdered?: (queue: string) => boolean;
  // The queues the prefetch plan keeps at the start value, ordered or not (the synchronization queues not read
  // yet): the plan only, the stop paths keep giving back their unstarted messages
  holdAtStart?: (queue: string) => boolean;
}

export interface PushConsumer {
  queue: string;
  alive: () => boolean;
  refresh: () => Promise<void>;
  isOrdered: (queue: string) => boolean;
  isConsuming: (queue: string) => boolean;
  // Stopped and draining: not consumed again before its channel is closed, even if listed again
  isStopping: (queue: string) => boolean;
  // Its messages delivered here, not answered yet (the queue lease: a platform holding them is not idle)
  inFlight: (queue: string) => number;
  close: () => Promise<void>;
}

// RabbitMQ binds a prefetch to a consumer when it is created and a live basic.qos does not change it; after a
// cancel, the unacked messages of the old consumer stay on the channel and do not count against the new one
// (RabbitMQ 4.3, probed 2026-11-17: 2 held + new prefetch 5 = 7). A change is a new consumer on the same
// channel, created once the messages in flight are down to the new prefetch: while it changes, a queue holds at
// most twice the largest credit live on its channel (the old consumer's messages, then the new one's credit).
type ConsumerPhase = 'starting' | 'consuming' | 'cancelling' | 'waiting';

interface ConsumedQueue {
  channel: amqp.Channel | null;
  consumerTag: string | null;
  phase: ConsumerPhase;
  inFlight: number;
  stopping: boolean;
  open: boolean;
  // An event message was delivered from it: consumed in order
  ordered: boolean;
  // Credit of the current (or last) consumer, and the prefetch planned for the queue
  prefetch: number;
  target: number;
  // Queues the queue shares the budgets with, from the last plan
  shares: number;
  // Ticks since a message was ready or in flight, the mean size of its ready messages (last read), and the
  // largest message delivered (decaying)
  idleTicks: number;
  meanReadyBytes: number;
  largest: number;
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
  const prefetchOptions = { initial: options.prefetch, totalBytes: options.prefetchTotalBytes, totalMessages: options.prefetchTotalMessages, max: options.maxPrefetch };
  const prefetchPlanned = options.prefetchTotalBytes > 0 && options.prefetchTotalMessages > 0;
  const initial = initialPrefetch(prefetchOptions);
  const order = createQueueOrder();
  const consumed = new Map<string, ConsumedQueue>();
  const toldOrdered = new Set<string>();
  let alive = true;
  let sizesUnread = false;
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

  const isOrderedQueue = (queue: string, entry: ConsumedQueue) => entry.ordered || order.isOrdered(queue) || !!options.isOrdered?.(queue);
  // A message not started when its queue stops (lease moved, connector removed, close) is given back at once
  // instead of being drained, up to the admission of its operations (handlePushMessage): only the ones started
  // need the drain. One waiting for a transformation slot is given back once it gets one. An ordered queue drains
  // them all, a later event given back while an earlier one still commits could be written first by another
  // platform. On a closed channel the broker already redelivers them all: none is started, ordered or not.
  const givenBack = (queue: string, entry: ConsumedQueue) => !entry.open || (entry.stopping && !isOrderedQueue(queue, entry));
  const handle = async (queue: string, entry: ConsumedQueue, channel: amqp.Channel, message: amqp.Message, data: Record<string, any> | null) => {
    const bytes = message.content.length;
    const stopped = () => givenBack(queue, entry);
    let outcome: PushOutcome = stoppedOutcome();
    // a waiter for the bytes is abandoned when its queue stops (stopQueue)
    if (!stopped() && await budget.acquire(bytes, entry)) {
      try {
        outcome = await handlePushMessage(data, queue, deps, stopped);
      } catch (cause) {
        logApp.error(`${LOG_PREFIX} push message handling failed`, { queue, cause });
        outcome = { ack: false, reason: 'transformation_failed', operations: 0, objects: 0 };
      } finally {
        budget.release(bytes);
      }
    }
    // given back because the broker closed its channel, not because its queue stopped
    if (outcome.reason === 'stopped' && !entry.open) outcome = { ...outcome, reason: 'channel_closed' };
    if (outcome.requeue && outcome.reason !== 'stopped' && outcome.reason !== 'channel_closed') {
      // given back after a pause: a classic queue redelivers it at once, and the engine needs time
      await new Promise((resolve) => {
        setTimeout(resolve, REQUEUE_DELAY_MS);
      });
    }
    if (entry.open) {
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
  const stopQueue = (queue: string, entry: ConsumedQueue) => {
    entry.stopping = true;
    if (!isOrderedQueue(queue, entry)) budget.abandon(entry);
    const { channel, consumerTag } = entry;
    // no channel yet, or starting or cancelling: stopped when the broker answers; waiting (no consumer, some
    // messages in flight): closed once they are answered
    if (!channel || !consumerTag) return;
    entry.consumerTag = null;
    try {
      // a failed cancel: the broker closes the channel (its close handler ends the entry); closing it here, before
      // amqplib's close-ok, would throw in amqplib's frame loop and close the whole connection
      channel.cancel(consumerTag, (cancelError) => {
        if (!cancelError && entry.inFlight === 0) closeChannel(channel);
      });
    } catch {
      // Already closing
    }
  };

  const inputOf = (queue: string, entry: ConsumedQueue): QueuePrefetchInput => ({
    queue,
    active: entry.idleTicks < ACTIVE_HOLD_TICKS,
    meanReadyBytes: entry.meanReadyBytes,
    largestRecentBytes: entry.largest,
    ordered: isOrderedQueue(queue, entry) || !!options.holdAtStart?.(queue),
  });
  // The consumer of a queue on its channel, with the entry's prefetch
  const startConsumer = (queue: string, entry: ConsumedQueue) => {
    const { channel } = entry;
    if (!channel || !entry.open) return;
    entry.phase = 'starting';
    try {
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
        entry.inFlight += 1;
        entry.idleTicks = 0;
        if (isEvent) entry.ordered = true;
        if (prefetchPlanned && (isEvent || message.content.length > entry.largest)) {
          // a larger message (or the first event) lowers the queue's prefetch at once, a smaller one waits for the
          // next plan
          entry.largest = Math.max(entry.largest, message.content.length);
          retarget(queue, entry, prefetchFor(inputOf(queue, entry), entry.shares, prefetchOptions), true);
        }
        order.schedule(queue, isEvent, () => handle(queue, entry, channel, message, data))
          .catch((cause) => logApp.error(`${LOG_PREFIX} push message scheduling failed`, { queue, cause }))
          .finally(() => answered(queue, entry));
      }, { noAck: false }, (consumeError, ok) => {
        if (consumeError) return; // the channel is closed with the error, its entry with it
        entry.phase = 'consuming';
        entry.consumerTag = ok.consumerTag;
        if (entry.stopping) {
          stopQueue(queue, entry);
        } else {
          applyTarget(queue, entry); // planned again while it was starting
        }
      });
    } catch (cause) {
      // the channel closed meanwhile (amqplib throws on a closed channel): its entry goes with it
      logApp.warn(`${LOG_PREFIX} consumer not created, channel closing`, { queue, cause });
    }
  };
  // A new consumer once the messages in flight are down to the planned prefetch
  const resume = (queue: string, entry: ConsumedQueue) => {
    if (entry.phase !== 'waiting' || entry.stopping || entry.inFlight > entry.target) return;
    entry.prefetch = entry.target;
    startConsumer(queue, entry);
  };
  // The consumer cancelled when the planned prefetch differs from its credit; the messages in flight stay
  // unacked on the channel and are answered on it, nothing is redelivered
  const applyTarget = (queue: string, entry: ConsumedQueue) => {
    if (entry.stopping) return;
    if (entry.phase === 'waiting') {
      resume(queue, entry);
      return;
    }
    const { channel, consumerTag } = entry;
    if (entry.target === entry.prefetch || entry.phase !== 'consuming' || !channel || !consumerTag) return; // starting or cancelling: on the broker's answer
    entry.phase = 'cancelling';
    entry.consumerTag = null;
    try {
      channel.cancel(consumerTag, (cancelError) => {
        if (cancelError) return; // the channel is closed with the error, its entry with it
        entry.phase = 'waiting';
        if (entry.stopping) {
          if (entry.inFlight === 0) closeChannel(channel);
          return;
        }
        resume(queue, entry);
      });
    } catch {
      // Already closing
    }
  };
  const retarget = (queue: string, entry: ConsumedQueue, planned: number, lowerOnly = false) => {
    const next = nextPrefetch(entry.target, planned, initial, heldToStart(inputOf(queue, entry)));
    if (next === null || (lowerOnly && next > entry.target)) return;
    logApp.debug(`${LOG_PREFIX} prefetch changed`, { queue, from: entry.target, to: next, shares: entry.shares });
    entry.target = next;
    applyTarget(queue, entry);
  };
  const answered = (queue: string, entry: ConsumedQueue) => {
    entry.inFlight -= 1;
    if (entry.stopping) {
      if (entry.inFlight === 0 && entry.channel) closeChannel(entry.channel);
    } else {
      resume(queue, entry);
    }
  };

  const consumeQueue = (queue: string) => {
    const prefetch = initial;
    const entry: ConsumedQueue = {
      channel: null,
      consumerTag: null,
      phase: 'starting',
      inFlight: 0,
      stopping: false,
      open: false,
      ordered: false,
      prefetch,
      target: prefetch,
      shares: 1,
      idleTicks: ACTIVE_HOLD_TICKS,
      meanReadyBytes: 0,
      largest: 0,
    };
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
        budget.abandon(entry);
        if (consumed.get(queue) === entry) consumed.delete(queue);
      });
      // stopped while its channel opened: no consumer
      if (entry.stopping) {
        closeChannel(channel);
        return;
      }
      // the first consumer takes the prefetch planned while its channel opened
      entry.prefetch = entry.target;
      startConsumer(queue, entry);
    });
  };

  // The prefetch of every queue consumed here, from the broker's sizes and what is in flight here
  const plan = async () => {
    if (!prefetchPlanned || !options.readSizes) return;
    let sizes: Map<string, QueueSize>;
    try {
      sizes = await options.readSizes();
    } catch (cause) {
      if (!sizesUnread) logApp.warn(`${LOG_PREFIX} queue sizes not read, prefetches kept until they are`, { cause });
      sizesUnread = true;
      return;
    }
    if (sizesUnread) logApp.info(`${LOG_PREFIX} queue sizes read again`);
    sizesUnread = false;
    const queues = [...consumed].filter(([, entry]) => !entry.stopping);
    queues.forEach(([queue, entry]) => {
      const size = sizes.get(queue);
      const ready = size?.ready ?? 0;
      Object.assign(entry, {
        meanReadyBytes: size && ready > 0 && size.bytesReady > 0 ? size.bytesReady / ready : 0,
        idleTicks: ready > 0 || entry.inFlight > 0 ? 0 : entry.idleTicks + 1,
      });
    });
    const planned = planPrefetch(queues.map(([queue, entry]) => inputOf(queue, entry)), prefetchOptions);
    queues.forEach(([queue, entry]) => {
      const { prefetch, shares } = planned.get(queue) ?? { prefetch: entry.target, shares: entry.shares };
      Object.assign(entry, { shares, largest: entry.idleTicks >= LARGEST_FORGET_IDLE_TICKS ? 0 : entry.largest * LARGEST_DECAY });
      retarget(queue, entry, prefetch);
    });
  };

  // A stopping queue is consumed again once its channel is closed (next refresh). A queue no longer listed
  // is stopped and drained on a single writer too (connector removed), not only when a lease moves.
  const refresh = async () => {
    if (!alive) return;
    const queues = new Set(await listQueues());
    [...queues].filter((queue) => !consumed.has(queue)).forEach(consumeQueue);
    [...consumed].filter(([queue, entry]) => !queues.has(queue) && !entry.stopping).forEach(([queue, entry]) => stopQueue(queue, entry));
    await plan();
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
  logApp.info(`${LOG_PREFIX} consuming`, { queues: consumed.size, prefetch: options.prefetch, prefetch_total_bytes: options.prefetchTotalBytes, prefetch_total_messages: options.prefetchTotalMessages, max_prefetch: options.maxPrefetch, max_in_flight_bytes: options.maxInFlightBytes });
  return {
    queue: 'push queues',
    alive: () => alive,
    refresh,
    isOrdered: (queue) => order.isOrdered(queue),
    isConsuming: (queue) => consumed.has(queue),
    isStopping: (queue) => consumed.get(queue)?.stopping ?? false,
    inFlight: (queue) => consumed.get(queue)?.inFlight ?? 0,
    close: async () => {
      alive = false;
      [...consumed].filter(([, entry]) => !entry.stopping).forEach(([queue, entry]) => stopQueue(queue, entry));
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
