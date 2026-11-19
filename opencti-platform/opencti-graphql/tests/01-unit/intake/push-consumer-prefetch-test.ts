import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import amqp from 'amqplib/callback_api';
import { logApp } from '../../../src/config/conf';
import { consumePushQueues, type PushConsumerOptions, type QueueSize } from '../../../src/intake/workerless/push-consumer';
import { handlePushMessage, type PushOutcome } from '../../../src/intake/workerless/push-intake';

// The prefetch changes of the push consumer against a fake broker (task 0040): a change cancels the consumer
// and creates another on the same channel, once the messages in flight are down to the new prefetch; a queue
// stopped meanwhile gets no new consumer, gives back its unstarted messages and closes once answered.

const intake = vi.hoisted(() => ({ pending: [] as Array<(outcome: PushOutcome) => void> }));
vi.mock('amqplib/callback_api', () => ({ default: { connect: vi.fn() } }));
vi.mock('../../../src/database/rabbitmq', async (importOriginal) => ({ ...(await importOriginal<object>()), rabbitmqUri: () => 'amqp://localhost', rabbitmqConnectionOptions: () => ({}) }));
vi.mock('../../../src/intake/workerless/push-intake', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  handlePushMessage: vi.fn(() => new Promise<PushOutcome>((resolve) => {
    intake.pending.push(resolve);
  })),
}));

type Answer = (error: unknown, ok?: { consumerTag: string }) => void;
interface PendingConsume { onMessage: (message: unknown) => void; answer: Answer; tag: string; credit: number; answered: boolean; unacked: number; seq: number }
interface PendingCancel { tag: string; answer: Answer; answered: boolean; seq: number }
// As amqplib and RabbitMQ: a consumer is registered when the broker answers its consume and keeps its credit (the
// prefetch sent before it), the broker delivers to it only under that credit and until its cancel is answered; the
// broker answers the calls in the order they were sent; a failed cancel closes the channel (cancelFails); any call
// on a closed (or closing) channel throws
class FakeChannel extends EventEmitter {
  closed = false;

  credit = 0;

  private seq = 0;

  private holders = new Map<unknown, PendingConsume>();

  private open() {
    if (this.closed) throw new Error('Channel closed');
  }

  private answered(message: unknown) {
    this.open();
    const holder = this.holders.get(message);
    if (holder) holder.unacked -= 1;
    this.holders.delete(message);
  }

  ack = vi.fn((message: unknown) => this.answered(message));

  nack = vi.fn((message: unknown) => this.answered(message));

  consumers: PendingConsume[] = [];

  cancels: PendingCancel[] = [];

  prefetch = vi.fn((count: number) => {
    this.open();
    this.credit = count;
  });

  consume = vi.fn((_queue: string, onMessage: (message: unknown) => void, _options: unknown, answer: Answer) => {
    this.open();
    this.seq += 1;
    this.consumers.push({ onMessage, answer, tag: `tag-${this.consumers.length + 1}`, credit: this.credit, answered: false, unacked: 0, seq: this.seq });
  });

  cancel = vi.fn((tag: string, answer: Answer) => {
    this.open();
    this.seq += 1;
    this.cancels.push({ tag, answer, answered: false, seq: this.seq });
  });

  // closed here: closing at once, closed on the broker's answer
  close = vi.fn(() => {
    this.open();
    this.closed = true;
    setImmediate(() => this.emit('close'));
  });

  // closed by the broker (channel error, failed cancel, connection lost): closed at once
  brokerCloses() {
    this.closed = true;
    this.emit('close');
  }

  // The broker answers what is pending, in the order sent, until nothing is
  settle() {
    for (;;) {
      if (this.closed) return;
      const next = [...this.cancels, ...this.consumers].filter((pending) => !pending.answered).sort((x, y) => x.seq - y.seq)[0];
      if (!next) return;
      next.answered = true;
      if ('credit' in next) {
        next.answer(null, { consumerTag: next.tag });
      } else {
        next.answer(null);
      }
    }
  }

  // As amqplib: the failed cancel is answered first, then the broker's close is accepted; a close sent from the
  // answer makes amqplib's close-ok throw in its frame loop, which closes the whole connection
  cancelFails() {
    const cancel = this.cancels.find((pending) => !pending.answered);
    if (cancel) {
      cancel.answered = true;
      cancel.answer(new Error('channel closed'));
      if (this.closed) throw new Error('Channel closing: close-ok not sent, the connection closes');
      this.brokerCloses();
    }
  }

  credits() {
    return this.consumers.map(({ credit }) => credit);
  }

  // To the last consumer registered and not cancelled yet, under its credit
  deliver(bytes: number, event = false) {
    const consumer = this.consumers.filter((pending) => pending.answered && !this.cancels.some((cancel) => cancel.answered && cancel.tag === pending.tag)).at(-1);
    if (this.closed || !consumer) throw new Error('no consumer to deliver to');
    if (consumer.unacked >= consumer.credit) throw new Error(`credit ${consumer.credit} exhausted: the broker would not deliver`);
    const content = event ? Buffer.from(JSON.stringify({ type: 'event', pad: 'x'.repeat(bytes) })) : Buffer.alloc(bytes, 'x');
    const message = { content, fields: {}, properties: {} };
    consumer.unacked += 1;
    this.holders.set(message, consumer);
    consumer.onMessage(message);
    return message;
  }
}

class FakeConnection extends EventEmitter {
  channels = new Map<number, FakeChannel>();

  close = vi.fn();

  // the broker answers a channel open later, as amqplib's RPC
  createChannel(callback: (error: unknown, channel: FakeChannel) => void) {
    const channel = new FakeChannel();
    this.channels.set(this.channels.size, channel);
    setImmediate(() => callback(null, channel));
  }
}

const KB = 1024;
const written: PushOutcome = { ack: true, reason: 'written', operations: 1, objects: 1 };
const flush = async () => {
  for (let i = 0; i < 20; i += 1) {
    await new Promise((resolve) => {
      setImmediate(resolve);
    });
  }
};
const answer = async (count = intake.pending.length) => {
  intake.pending.splice(0, count).forEach((resolve) => resolve(written));
  await flush();
};
// 1 MB shared, bound 100: messages of 1 KB plan the bound, a 512 KB one plans 2
const baseOptions: PushConsumerOptions = { prefetch: 25, prefetchTotalBytes: 1024 * KB, prefetchTotalMessages: 600, maxPrefetch: 100, maxInFlightBytes: 1024 * 1024 * KB };
const small = (ready = 1000): QueueSize => ({ ready, bytesReady: ready * KB });

describe('push consumer prefetch changes (task 0040)', () => {
  let connection: FakeConnection;
  let queues: string[];
  let sizes: Map<string, QueueSize>;
  let readSizes: Mock<() => Promise<Map<string, QueueSize>>>;
  let outcomes: string[];
  const start = async (options: Partial<PushConsumerOptions> = {}) => {
    const consumer = await consumePushQueues(async () => queues, {} as any, { ...baseOptions, readSizes, ...options }, (outcome) => outcomes.push(outcome.reason));
    await flush();
    return { consumer, channel: connection.channels.get(0) as FakeChannel };
  };
  const tick = async (consumer: { refresh: () => Promise<void> }, channel?: FakeChannel) => {
    await consumer.refresh();
    channel?.settle();
    await flush();
  };
  // Started, then raised x2 per tick from 25 to the bound (100)
  const startRaised = async () => {
    const started = await start();
    started.channel.settle();
    await tick(started.consumer, started.channel);
    expect(started.channel.credits()).toEqual([50, 100]);
    return started;
  };

  beforeEach(() => {
    intake.pending.length = 0;
    outcomes = [];
    connection = new FakeConnection();
    vi.mocked(amqp.connect).mockImplementation(((_uri: string, _options: unknown, callback: (error: unknown, opened: unknown) => void) => callback(null, connection)) as any);
    queues = ['push_a'];
    sizes = new Map([['push_a', small()]]);
    readSizes = vi.fn<() => Promise<Map<string, QueueSize>>>(async () => sizes);
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should count the raw bytes it holds, delivered then handled, down to zero once answered (task 0040 memory)', async () => {
    const { consumer, channel } = await startRaised();
    channel.deliver(3 * KB);
    channel.deliver(KB);
    await flush();
    expect(consumer.memory()).toEqual({ deliveredBytes: 4 * KB, deliveredMessages: 2, handlingBytes: 4 * KB, waitingMessages: 0 });
    expect(consumer.takeLargestDelivered()).toBe(3 * KB);
    expect(consumer.takeLargestDelivered()).toBe(0); // since the previous call
    await answer();
    expect(consumer.memory()).toEqual({ deliveredBytes: 0, deliveredMessages: 0, handlingBytes: 0, waitingMessages: 0 });
  });

  it('should create the first consumer with the prefetch planned while its channel opened', async () => {
    const { channel } = await start();
    expect(channel.credits()).toEqual([50]); // 25 raised x2 by the first plan, before the channel answered
    channel.settle();
    expect(channel.cancel).not.toHaveBeenCalled();
  });

  it('should apply on its start a prefetch planned while the consumer was starting', async () => {
    const { consumer, channel } = await start();
    await consumer.refresh(); // 50 -> 100 planned, the first consumer not answered yet
    expect(channel.cancel).not.toHaveBeenCalled();
    channel.settle();
    expect(channel.credits()).toEqual([50, 100]);
  });

  it('should raise at most x2 per tick, each consumer created with its prefetch sent first', async () => {
    const { consumer, channel } = await startRaised();
    await tick(consumer, channel); // at the bound: kept
    expect(channel.credits()).toEqual([50, 100]);
    expect(channel.prefetch.mock.invocationCallOrder[1]).toBeLessThan(channel.consume.mock.invocationCallOrder[1]);
  });

  it('should answer the old consumer\'s messages on the same channel once, and create the new one on its cancel answer', async () => {
    const { consumer, channel } = await start();
    channel.settle();
    await consumer.refresh(); // cancel sent
    const early = channel.deliver(KB); // to the old consumer, before the cancel is answered
    await flush();
    expect(channel.consume).toHaveBeenCalledTimes(1);
    channel.settle();
    expect(channel.credits()).toEqual([50, 100]);
    await answer();
    expect(channel.ack).toHaveBeenCalledTimes(1);
    expect(channel.ack).toHaveBeenCalledWith(early);
    expect(channel.nack).not.toHaveBeenCalled();
    expect(channel.close).not.toHaveBeenCalled();
  });

  it('should create no new consumer when messages are answered while consuming', async () => {
    const { channel } = await startRaised();
    for (let i = 0; i < 5; i += 1) channel.deliver(KB);
    await flush();
    await answer();
    expect(channel.consume).toHaveBeenCalledTimes(2);
    expect(channel.ack).toHaveBeenCalledTimes(5);
  });

  it('should create the lowered consumer only once the messages in flight are down to the new prefetch', async () => {
    const { consumer, channel } = await startRaised();
    for (let i = 0; i < 5; i += 1) channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]); // plans 2
    await consumer.refresh();
    channel.settle(); // cancelled: 5 in flight > 2, no consumer yet
    expect(channel.consume).toHaveBeenCalledTimes(2);
    await answer(2);
    expect(channel.consume).toHaveBeenCalledTimes(2); // 3 in flight
    await answer(1);
    expect(channel.credits()).toEqual([50, 100, 2]); // 2 in flight: created with 2
    await answer();
    expect(channel.ack).toHaveBeenCalledTimes(5);
  });

  it('should create the consumer at once when a waiting queue is planned higher again, back to its old credit', async () => {
    const { consumer, channel } = await startRaised();
    for (let i = 0; i < 5; i += 1) channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]);
    await consumer.refresh();
    channel.settle(); // waiting at 2, 5 in flight
    sizes = new Map([['push_a', small()]]);
    await consumer.refresh(); // 2 -> 4 (x2): 5 in flight > 4, still waiting
    expect(channel.consume).toHaveBeenCalledTimes(2);
    await answer(1); // 4 in flight
    expect(channel.credits()).toEqual([50, 100, 4]);
  });

  it('should resume a waiting queue planned back to the credit of its last consumer, without an answer', async () => {
    const { consumer, channel } = await startRaised();
    for (let i = 0; i < 70; i += 1) channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 17 * KB }]]); // plans 60: under 3/4 of 100
    await consumer.refresh();
    channel.settle(); // waiting at 60, 70 in flight
    expect(channel.consume).toHaveBeenCalledTimes(2);
    sizes = new Map([['push_a', small()]]);
    await consumer.refresh(); // back to 100, the credit of the cancelled consumer: 70 in flight <= 100
    expect(channel.credits()).toEqual([50, 100, 100]);
  });

  it('should lower at once on a larger message, a second one before the answer cancelling nothing more', async () => {
    const { channel } = await startRaised();
    channel.deliver(512 * KB); // 1 MB / 512 KB = 2
    expect(channel.cancel).toHaveBeenCalledTimes(2);
    channel.deliver(700 * KB); // plans 1 while cancelling: applied on the answer
    expect(channel.cancel).toHaveBeenCalledTimes(2);
    await flush();
    channel.settle(); // 2 in flight > 1
    await answer(1);
    expect(channel.credits()).toEqual([50, 100, 1]);
  });

  it('should keep a queue lowered by a large message for ticks, a smaller one in the same tick not undoing it', async () => {
    const { consumer, channel } = await startRaised();
    channel.deliver(512 * KB);
    channel.deliver(KB); // smaller: the largest stays
    await flush();
    channel.settle();
    await answer();
    channel.settle();
    expect(channel.credits()).toEqual([50, 100, 2]);
    // small messages ready again: the large one, halved every 6 ticks, keeps it low for 6 ticks (a plan of 3 is not
    // 2 above), then raised back slowly
    for (let i = 0; i < 6; i += 1) await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100, 2]);
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100, 2, 4]);
  });

  it('should keep a queue active a few ticks after its last message, then plan it idle', async () => {
    queues = ['push_a', 'push_b'];
    sizes = new Map([['push_a', small()], ['push_b', small(0)]]);
    const { consumer } = await start();
    const a = connection.channels.get(0) as FakeChannel;
    const b = connection.channels.get(1) as FakeChannel;
    a.settle();
    b.settle();
    await tick(consumer, a);
    expect(a.credits()).toEqual([50, 100]); // the only active queue
    expect(b.credits()).toEqual([25]); // idle: min(25, 600 / 2)
    a.deliver(KB); // its size known from what it delivered, nothing ready any more
    await flush();
    await answer();
    sizes = new Map([['push_a', small(0)], ['push_b', small(0)]]);
    await tick(consumer, a);
    await tick(consumer, a);
    expect(a.cancel).toHaveBeenCalledTimes(1); // still active for its third tick
    await tick(consumer, a);
    expect(a.credits()).toEqual([50, 100, 25]); // idle: min(25, 600 / 2)
  });

  it('should keep a queue active while its messages are in flight here, none ready', async () => {
    queues = ['push_a', 'push_b'];
    sizes = new Map([['push_a', small()], ['push_b', small(0)]]);
    const { consumer } = await start();
    const a = connection.channels.get(0) as FakeChannel;
    (connection.channels.get(1) as FakeChannel).settle();
    a.settle();
    await tick(consumer, a);
    a.deliver(KB); // never answered in this test
    await flush();
    sizes = new Map([['push_a', small(0)], ['push_b', small(0)]]);
    for (let i = 0; i < 5; i += 1) await tick(consumer, a);
    expect(a.credits()).toEqual([50, 100]);
  });

  it('should keep an ordered queue at the start value, known before its first event', async () => {
    const { consumer, channel } = await start({ isOrdered: (queue) => queue === 'push_a' });
    channel.settle();
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([25]);
    expect(channel.cancel).not.toHaveBeenCalled();
  });

  it('should lower a raised queue to the start value at its first event', async () => {
    const { consumer, channel } = await startRaised();
    channel.deliver(2 * KB); // the event below is smaller than the largest: its type lowers it, not its size
    await flush();
    channel.deliver(KB, true);
    expect(channel.cancel).toHaveBeenCalledTimes(2);
    await flush();
    channel.settle();
    await answer();
    expect(channel.credits()).toEqual([50, 100, 25]);
    await tick(consumer, channel); // ordered: never raised again
    expect(channel.credits()).toEqual([50, 100, 25]);
    await answer(); // the event, run once the message before it is answered (ordered)
    expect(channel.ack).toHaveBeenCalledTimes(2);
  });

  it('should drain an ordered queue on stop, giving back none of its events', async () => {
    const { consumer, channel } = await start({ isOrdered: () => true });
    channel.settle();
    channel.deliver(KB, true); // started
    channel.deliver(KB, true); // waits for the first in the order chain
    await flush();
    queues = [];
    await tick(consumer, channel);
    await answer(1);
    await answer(1);
    expect(channel.nack).not.toHaveBeenCalled();
    expect(channel.ack).toHaveBeenCalledTimes(2);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should keep, on stop, an ordered queue\'s event waiting for the byte budget', async () => {
    queues = ['push_a', 'push_b'];
    const { consumer } = await start({ readSizes: undefined, maxInFlightBytes: 1, isOrdered: (queue) => queue === 'push_b' });
    const a = connection.channels.get(0) as FakeChannel;
    const b = connection.channels.get(1) as FakeChannel;
    a.settle();
    b.settle();
    a.deliver(KB); // holds the byte budget
    await flush();
    b.deliver(KB, true); // waits for it
    await flush();
    queues = ['push_a'];
    await consumer.refresh();
    b.settle();
    await flush();
    expect(b.nack).not.toHaveBeenCalled();
    await answer(); // a's message answered: the event starts
    await answer();
    expect(b.ack).toHaveBeenCalledTimes(1);
    expect(b.close).toHaveBeenCalledTimes(1);
  });

  it('should give back at once a message waiting for the byte budget when its queue stops', async () => {
    const { consumer, channel } = await start({ readSizes: undefined, maxInFlightBytes: 1 });
    channel.settle();
    channel.deliver(KB); // started (alone, it always starts)
    const waiting = channel.deliver(KB); // waits for the byte budget
    await flush();
    queues = [];
    await consumer.refresh();
    await flush();
    expect(channel.nack).toHaveBeenCalledWith(waiting, false, true); // before the started one is answered
    expect(channel.ack).not.toHaveBeenCalled();
    // the started one is told its queue stopped: given back if not admitted yet (handlePushMessage)
    const stopped = vi.mocked(handlePushMessage).mock.calls.at(-1)?.[3];
    expect(stopped?.()).toBe(true);
    channel.settle();
    await answer();
    expect(channel.ack).toHaveBeenCalledTimes(1);
    expect(intake.pending.length).toBe(0);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should give back at once a message delivered after its queue stopped, before the cancel answer', async () => {
    const { consumer, channel } = await start({ readSizes: undefined });
    channel.settle();
    channel.deliver(KB);
    await flush();
    queues = [];
    await consumer.refresh(); // cancel sent, not answered
    const late = channel.deliver(KB);
    await flush();
    expect(channel.nack).toHaveBeenCalledWith(late, false, true);
    channel.settle();
    await answer();
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should give a queue stopped while cancelling no new consumer, and close it once answered', async () => {
    const { consumer, channel } = await startRaised();
    channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]);
    await consumer.refresh(); // cancel sent
    queues = [];
    await consumer.refresh(); // stopped before the cancel is answered
    channel.settle();
    expect(channel.consume).toHaveBeenCalledTimes(2);
    expect(channel.close).not.toHaveBeenCalled(); // one message in flight
    await answer();
    expect(channel.ack).toHaveBeenCalledTimes(1);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should close at once a queue stopped while cancelling with nothing in flight', async () => {
    const { consumer, channel } = await startRaised();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]);
    await consumer.refresh();
    queues = [];
    await consumer.refresh();
    expect(channel.close).not.toHaveBeenCalled();
    channel.settle();
    expect(channel.close).toHaveBeenCalledTimes(1);
    expect(channel.consume).toHaveBeenCalledTimes(2);
  });

  it('should close a queue stopped while waiting for its messages in flight, without a new consumer', async () => {
    const { consumer, channel } = await startRaised();
    for (let i = 0; i < 5; i += 1) channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]);
    await consumer.refresh();
    channel.settle(); // waiting: 5 in flight > 2
    queues = [];
    await consumer.refresh();
    expect(channel.close).not.toHaveBeenCalled();
    await answer();
    expect(channel.consume).toHaveBeenCalledTimes(2);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should cancel a consumer whose queue stopped while it was starting', async () => {
    const { consumer, channel } = await start({ readSizes: undefined });
    queues = [];
    await consumer.refresh();
    expect(channel.cancel).not.toHaveBeenCalled();
    channel.settle();
    expect(channel.cancel).toHaveBeenCalledWith('tag-1', expect.any(Function));
    expect(channel.close).toHaveBeenCalledTimes(1);
    expect(channel.consume).toHaveBeenCalledTimes(1);
  });

  it('should create no consumer on a channel closed while waiting', async () => {
    const { consumer, channel } = await startRaised();
    for (let i = 0; i < 5; i += 1) channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]);
    await consumer.refresh();
    channel.settle(); // waiting
    const warn = vi.spyOn(logApp, 'warn');
    channel.brokerCloses();
    await answer();
    expect(channel.consume).toHaveBeenCalledTimes(2);
    expect(warn.mock.calls.some(([message]) => String(message).includes('consumer not created'))).toBe(false); // not even tried
    expect(consumer.isConsuming('push_a')).toBe(false);
  });

  it('should keep the prefetches while the sizes cannot be read, warning once per outage', async () => {
    const warn = vi.spyOn(logApp, 'warn');
    const info = vi.spyOn(logApp, 'info');
    const { consumer, channel } = await start();
    channel.settle();
    readSizes.mockRejectedValue(new Error('management down'));
    queues = ['push_a', 'push_b'];
    await tick(consumer, channel);
    await tick(consumer, channel);
    expect(connection.channels.size).toBe(2); // a new queue is still consumed
    expect(channel.cancel).not.toHaveBeenCalled();
    expect(channel.credits()).toEqual([50]);
    const notRead = () => warn.mock.calls.filter(([message]) => String(message).includes('queue sizes not read')).length;
    expect(notRead()).toBe(1);
    readSizes.mockImplementation(async () => sizes);
    await tick(consumer, channel);
    expect(info.mock.calls.some(([message]) => String(message).includes('queue sizes read again'))).toBe(true);
    readSizes.mockRejectedValue(new Error('management down again'));
    await tick(consumer, channel);
    expect(notRead()).toBe(2);
  });

  it('should keep the prefetch fixed without a budget: no size read, no change on a large message', async () => {
    const { channel } = await start({ prefetchTotalBytes: 0 });
    channel.settle();
    channel.deliver(900 * KB);
    expect(readSizes).not.toHaveBeenCalled();
    expect(channel.cancel).not.toHaveBeenCalled();
    expect(channel.credits()).toEqual([25]);
  });

  it('should not raise a queue on a delivery: its share is known from the plans only', async () => {
    const { channel } = await start({ readSizes: undefined });
    channel.settle();
    channel.deliver(KB);
    expect(channel.cancel).not.toHaveBeenCalled();
  });

  it('should create no consumer after a failed cancel', async () => {
    const { consumer, channel } = await start();
    channel.settle();
    await consumer.refresh();
    channel.cancelFails();
    await flush();
    expect(channel.consume).toHaveBeenCalledTimes(1);
  });

  it('should count the messages in flight of a queue for the lease', async () => {
    const { consumer, channel } = await start();
    channel.settle();
    channel.deliver(KB);
    channel.deliver(KB);
    await flush();
    expect(consumer.inFlight('push_a')).toBe(2);
    await answer();
    expect(consumer.inFlight('push_a')).toBe(0);
    expect(consumer.inFlight('push_unknown')).toBe(0);
  });

  it('should give back, on a channel closed without a stop, the messages not started, none of them answered', async () => {
    const { channel } = await start({ readSizes: undefined, maxInFlightBytes: 1 });
    channel.settle();
    channel.deliver(KB); // started
    channel.deliver(KB); // waits for the byte budget
    await flush();
    expect(handlePushMessage).toHaveBeenCalledTimes(1);
    channel.brokerCloses();
    await flush();
    // the started one is told its channel is gone: given back if not admitted yet (handlePushMessage)
    expect(vi.mocked(handlePushMessage).mock.calls.at(-1)?.[3]?.()).toBe(true);
    await answer();
    expect(handlePushMessage).toHaveBeenCalledTimes(1); // the waiting one never started
    expect(channel.ack).not.toHaveBeenCalled();
    expect(channel.nack).not.toHaveBeenCalled();
    expect(outcomes).toContain('channel_closed'); // not counted as a stop
    expect(outcomes).not.toContain('stopped');
  });

  it('should give back, on a closed channel, the unstarted events of an ordered queue too', async () => {
    const { channel } = await start({ readSizes: undefined, isOrdered: () => true });
    channel.settle();
    channel.deliver(KB, true); // started
    channel.deliver(KB, true); // waits for the first in the order chain
    await flush();
    channel.brokerCloses();
    await answer();
    await flush();
    expect(handlePushMessage).toHaveBeenCalledTimes(1);
  });

  it('should create no consumer for a queue stopped before its channel opened, and consume it again later', async () => {
    const consumer = await consumePushQueues(async () => queues, {} as any, { ...baseOptions, readSizes }, () => {});
    queues = [];
    await consumer.refresh(); // its channel not answered yet
    await flush();
    const channel = connection.channels.get(0) as FakeChannel;
    expect(channel.consume).not.toHaveBeenCalled();
    expect(channel.close).toHaveBeenCalledTimes(1);
    expect(consumer.isConsuming('push_a')).toBe(false);
    queues = ['push_a'];
    await consumer.refresh();
    await flush();
    expect((connection.channels.get(1) as FakeChannel).consume).toHaveBeenCalledTimes(1);
  });

  it('should report a stopped queue as stopping until its drain ends, not consumed again when listed again', async () => {
    const { consumer, channel } = await start();
    channel.settle();
    channel.deliver(KB); // started: drained on stop
    await flush();
    queues = [];
    await tick(consumer, channel);
    expect(consumer.isConsuming('push_a')).toBe(true);
    expect(consumer.isStopping('push_a')).toBe(true);
    queues = ['push_a'];
    await tick(consumer, channel);
    expect(consumer.isStopping('push_a')).toBe(true);
    expect(channel.consume).toHaveBeenCalledTimes(1);
    await answer();
    expect(consumer.isConsuming('push_a')).toBe(false);
    expect(consumer.isStopping('push_a')).toBe(false);
  });

  it('should forget the largest message of a queue calm for a long time: its size is unknown again', async () => {
    const { consumer, channel } = await startRaised();
    channel.deliver(512 * KB);
    await flush();
    channel.settle();
    await answer();
    channel.settle();
    expect(channel.credits()).toEqual([50, 100, 2]);
    sizes = new Map([['push_a', small(0)]]);
    for (let i = 0; i < 70; i += 1) await tick(consumer, channel);
    expect(channel.credits().at(-1)).toBe(25); // idle: up to the start value
    // messages ready again, their bytes not sampled yet: not raised from the decayed size of the old large one
    sizes = new Map([['push_a', { ready: 1000, bytesReady: 0 }]]);
    for (let i = 0; i < 4; i += 1) await tick(consumer, channel);
    expect(channel.credits().at(-1)).toBe(25);
  });

  it('should lower on a larger message within the queue\'s share of the budgets, not as if it were alone', async () => {
    queues = ['push_a', 'push_b'];
    sizes = new Map([['push_a', small()], ['push_b', small()]]);
    const { consumer } = await start();
    const a = connection.channels.get(0) as FakeChannel;
    const b = connection.channels.get(1) as FakeChannel;
    a.settle();
    b.settle();
    await tick(consumer, a);
    b.settle();
    expect(a.credits()).toEqual([50, 100]); // 2 active: bound 100 each
    a.deliver(300 * KB); // 512 KB each / 300 KB = 1 (alone: 1 MB / 300 KB = 3)
    await flush();
    a.settle();
    await answer();
    expect(a.credits()).toEqual([50, 100, 1]);
  });

  it('should give back at once a message waiting for the byte budget when its queue stops while waiting for a lower consumer', async () => {
    const { consumer, channel } = await start({ maxInFlightBytes: KB });
    channel.settle();
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100]);
    channel.deliver(KB); // started, holds the byte budget
    const waiting = channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 700 * KB }]]); // plans 1
    await consumer.refresh();
    channel.settle(); // waiting: 2 in flight > 1
    queues = [];
    await consumer.refresh();
    await flush();
    expect(channel.nack).toHaveBeenCalledWith(waiting, false, true);
    await answer();
    expect(channel.credits()).toEqual([50, 100]);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should give back at once a message waiting for the byte budget when its queue stops while cancelling', async () => {
    const { consumer, channel } = await start({ maxInFlightBytes: KB });
    channel.settle();
    await tick(consumer, channel);
    channel.deliver(KB);
    const waiting = channel.deliver(KB);
    await flush();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 700 * KB }]]);
    await consumer.refresh(); // cancel sent, not answered
    queues = [];
    await consumer.refresh();
    await flush();
    expect(channel.nack).toHaveBeenCalledWith(waiting, false, true);
    channel.settle();
    await answer();
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should drain, on stop, a queue known ordered before any event: its waiting message is not given back', async () => {
    const { consumer, channel } = await start({ readSizes: undefined, maxInFlightBytes: 1, isOrdered: () => true });
    channel.settle();
    channel.deliver(KB);
    channel.deliver(KB); // waits for the byte budget
    await flush();
    queues = [];
    await consumer.refresh();
    await flush();
    expect(channel.nack).not.toHaveBeenCalled();
    channel.settle();
    await answer();
    await answer();
    expect(channel.ack).toHaveBeenCalledTimes(2);
    expect(channel.close).toHaveBeenCalledTimes(1);
  });

  it('should drain, on stop, a queue seen carrying an event: its waiting message is not given back', async () => {
    const { consumer, channel } = await start({ readSizes: undefined, maxInFlightBytes: 1 });
    channel.settle();
    channel.deliver(KB, true);
    channel.deliver(KB, true); // waits for the first in the order chain
    await flush();
    queues = [];
    await consumer.refresh();
    channel.settle();
    await answer();
    await answer();
    expect(channel.nack).not.toHaveBeenCalled();
    expect(channel.ack).toHaveBeenCalledTimes(2);
  });

  it('should start a new queue idle: it does not share the budgets before it has messages', async () => {
    queues = ['push_a', 'push_b'];
    sizes = new Map([['push_a', small()], ['push_b', small(0)]]);
    const { consumer } = await start({ prefetchTotalMessages: 100 });
    const a = connection.channels.get(0) as FakeChannel;
    a.settle();
    (connection.channels.get(1) as FakeChannel).settle();
    await tick(consumer, a);
    expect(a.credits()).toEqual([50, 100]); // alone among the active: 100, not 100 / 2
  });

  it('should keep a queue with messages ready active, nothing in flight here', async () => {
    const { consumer, channel } = await startRaised();
    for (let i = 0; i < 5; i += 1) await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100]);
  });

  it('should not keep the mean size of the ready messages once none is ready', async () => {
    const { consumer, channel } = await startRaised();
    sizes = new Map([['push_a', { ready: 10, bytesReady: 10 * 512 * KB }]]);
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100, 2]);
    channel.deliver(KB); // its size known from what it delivers
    await flush();
    await answer();
    sizes = new Map([['push_a', small(0)]]);
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100, 2, 4]);
  });

  it('should make a queue active again on a delivery answered before the next plan', async () => {
    const { consumer, channel } = await startRaised();
    channel.deliver(KB);
    await flush();
    await answer();
    sizes = new Map([['push_a', small(0)]]);
    for (let i = 0; i < 3; i += 1) await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100, 25]); // idle
    channel.deliver(KB);
    await flush();
    await answer();
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([50, 100, 25, 50]); // active again: raised
  });

  it('should leave a stopping queue out of the shares of the others', async () => {
    queues = ['push_a', 'push_b'];
    sizes = new Map([['push_a', small()], ['push_b', small()]]);
    const { consumer } = await start({ prefetchTotalMessages: 100 });
    const a = connection.channels.get(0) as FakeChannel;
    const b = connection.channels.get(1) as FakeChannel;
    a.settle();
    b.settle();
    expect(a.credits()).toEqual([50]); // 2 active: 100 / 2
    b.deliver(KB); // keeps b draining once stopped
    await flush();
    queues = ['push_a'];
    await tick(consumer, a);
    expect(a.credits()).toEqual([50, 100]); // alone
  });

  it('should close: every queue stopped, drained, then the connection', async () => {
    const { consumer, channel } = await start({ readSizes: undefined });
    channel.settle();
    channel.deliver(KB);
    await flush();
    const closing = consumer.close();
    channel.settle();
    await flush();
    expect(connection.close).not.toHaveBeenCalled(); // one message in flight
    await answer();
    await closing;
    expect(channel.ack).toHaveBeenCalledTimes(1);
    expect(channel.close).toHaveBeenCalledTimes(1);
    expect(connection.close).toHaveBeenCalledTimes(1);
    expect(consumer.alive()).toBe(false);
  });

  it('should lower a queue gone idle among 25 queues or more under the start value, from inside the 3/4 band', async () => {
    queues = Array.from({ length: 25 }, (_, i) => `push_${i}`);
    sizes = new Map(queues.map((queue) => [queue, small(0)]));
    sizes.set('push_0', small());
    const { consumer } = await start({ maxPrefetch: 32 });
    const channels = [...connection.channels.values()];
    channels.forEach((channel) => channel.settle());
    const a = channels[0];
    expect(a.credits()).toEqual([32]); // the only active one: the bound
    a.deliver(KB); // its size known from what it delivered
    await flush();
    await answer();
    sizes.set('push_0', small(0));
    for (let i = 0; i < 3; i += 1) await tick(consumer, a);
    expect(a.credits()).toEqual([32, 24]); // idle: min(25, 600 / 25)
    expect(channels[1].credits()).toEqual([25]); // idle from the start: kept at the start value, no ratchet under it
  });

  it('should keep the queues held at the start value at it without changing their stop: unstarted messages given back', async () => {
    const { consumer, channel } = await start({ maxInFlightBytes: 1, holdAtStart: () => true });
    channel.settle();
    await tick(consumer, channel);
    expect(channel.credits()).toEqual([25]); // never raised
    channel.deliver(KB);
    const waiting = channel.deliver(KB);
    await flush();
    queues = [];
    await consumer.refresh();
    await flush();
    expect(channel.nack).toHaveBeenCalledWith(waiting, false, true);
  });

  it('should not close the channel itself on a failed cancel of a stop: the broker closes it', async () => {
    const { consumer, channel } = await start({ readSizes: undefined });
    channel.settle();
    queues = [];
    await consumer.refresh(); // cancel sent
    expect(() => channel.cancelFails()).not.toThrow();
    expect(channel.close).not.toHaveBeenCalled();
    await flush();
    expect(consumer.isConsuming('push_a')).toBe(false);
  });
});
