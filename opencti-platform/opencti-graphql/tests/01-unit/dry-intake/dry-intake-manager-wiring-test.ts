import { EventEmitter } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import amqp from 'amqplib/callback_api';
import '../../../src/modules/index';
import { connectorsForWorker } from '../../../src/modules/connector/connector-domain';
import { initDryIntakeManager, type DryIntakeOptions } from '../../../src/intake/dry-intake/dry-intake-manager';

// The manager against a fake broker: what it asks the broker (prefetch, manual acks), on which
// channel it answers, what a closed or cancelled channel does, and when it starts consuming.

const meter = vi.hoisted(() => {
  const counters = new Map<string, { add: ReturnType<typeof vi.fn> }>();
  const gauges = new Map<string, (result: { observe: (value: number) => void }) => void>();
  const create = {
    createCounter: (name: string) => {
      const counter = { add: vi.fn() };
      counters.set(name, counter);
      return counter;
    },
    createHistogram: () => ({ record: vi.fn() }),
    createObservableGauge: (name: string) => ({ addCallback: (callback: (result: { observe: (value: number) => void }) => void) => gauges.set(name, callback) }),
  };
  return { counters, gauges, getMeter: () => create };
});

vi.mock('amqplib/callback_api', () => ({ default: { connect: vi.fn() } }));
vi.mock('../../../src/config/tracing', async (importOriginal) => ({ ...(await importOriginal<object>()), meterManager: { meterProvider: { getMeter: meter.getMeter } } }));
vi.mock('../../../src/database/rabbitmq', async (importOriginal) => ({ ...(await importOriginal<object>()), rabbitmqUri: () => 'amqp://localhost', rabbitmqConnectionOptions: () => ({}) }));
vi.mock('../../../src/modules/connector/connector-domain', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  connectorsForWorker: vi.fn(async () => [{ config: { push: 'push_a' } }]),
}));

class FakeChannel extends EventEmitter {
  prefetch = vi.fn();

  ack = vi.fn();

  nack = vi.fn();

  consume = vi.fn();

  close = vi.fn(() => {
    this.emit('close');
  });

  deliver(message: unknown) {
    const [, onMessage] = this.consume.mock.calls[0];
    onMessage(message);
  }
}

class FakeConnection extends EventEmitter {
  channels: FakeChannel[] = [];

  // As amqplib closes a connection (_closeChannels): each channel closes first, then the connection
  lose = () => {
    this.channels.forEach((channel) => channel.emit('close'));
    this.emit('close');
  };

  close = vi.fn(() => this.lose());

  createChannel(callback: (error: unknown, channel: FakeChannel) => void) {
    const channel = new FakeChannel();
    this.channels.push(channel);
    callback(null, channel);
  }
}

const wait = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});
const malware = { type: 'malware', spec_version: '2.1', id: 'malware--10000000-0000-4000-8000-000000000001', name: 'malware', is_family: true };
const delivery = (objects: unknown[]) => ({
  content: Buffer.from(JSON.stringify({ content: Buffer.from(JSON.stringify({ type: 'bundle', id: 'bundle--10000000-0000-4000-8000-000000000000', objects })).toString('base64') })),
  fields: { routingKey: 'push_routing_a' },
  properties: {},
});
const counted = (name: string) => meter.counters.get(name)?.add.mock.calls ?? [];
const gauge = (name: string) => {
  let value: number | undefined;
  meter.gauges.get(name)?.({ observe: (observed) => {
    value = observed;
  } });
  return value;
};

describe('Dry intake manager: consumption of the push queues', () => {
  const options: DryIntakeOptions = { rung: 'ack', prefetch: 7, startDelayS: 0, metricsEnabled: true };
  let connection: FakeConnection;
  let manager: ReturnType<typeof initDryIntakeManager> | null;
  const started = async (changes: Partial<DryIntakeOptions> = {}) => {
    manager = initDryIntakeManager({ ...options, ...changes });
    await expect(manager.start()).resolves.toBe(true);
    await wait(20);
    return connection.channels[0];
  };
  beforeEach(() => {
    connection = new FakeConnection();
    vi.mocked(amqp.connect).mockReset();
    const connect = (_uri: unknown, _options: unknown, callback: (error: unknown, opened: FakeConnection) => void) => callback(null, connection);
    vi.mocked(amqp.connect).mockImplementation(connect as any);
  });
  afterEach(async () => {
    await manager?.shutdown();
    manager = null;
    vi.useRealTimers();
  });
  it('should consume each queue with the prefetch per consumer and manual acks', async () => {
    const channel = await started();
    expect(channel.prefetch.mock.calls).toEqual([[7, false]]);
    expect(channel.consume).toHaveBeenCalledTimes(1);
    expect(channel.consume.mock.calls[0][0]).toEqual('push_a');
    expect(channel.consume.mock.calls[0][2]).toEqual({ noAck: false });
    expect(gauge('opencti_dry_intake_queues')).toEqual(1);
  });
  it('should ack each delivery on the channel it came on', async () => {
    const channel = await started();
    const message = delivery([malware]);
    channel.deliver(message);
    await wait(20);
    expect(channel.ack.mock.calls).toEqual([[message]]);
    expect(counted('opencti_dry_intake_messages')).toEqual([[1, { rung: 'ack', result: 'acked' }]]);
  });
  it('should not answer on a closed channel, and count the delivery as dropped', async () => {
    const channel = await started();
    channel.emit('close');
    channel.deliver(delivery([malware]));
    await wait(20);
    expect(channel.ack).not.toHaveBeenCalled();
    expect(counted('opencti_dry_intake_messages')).toEqual([[1, { rung: 'ack', result: 'dropped' }]]);
    expect(gauge('opencti_dry_intake_queues')).toEqual(0);
    // Redelivered and handled again: the drop does not end the window, nor takes a snapshot
    expect(gauge('opencti_dry_intake_first_start_timestamp_seconds')).toBeDefined();
    const snapshots = ['last_ack_timestamp_seconds', 'cpu_seconds', 'rss_max_bytes', 'eventloop_lag_p99_seconds', 'eventloop_lag_max_seconds'];
    expect(snapshots.map((name) => gauge(`opencti_dry_intake_${name}`))).toEqual(snapshots.map(() => undefined));
  });
  // A delivery waiting when its channel closes is redelivered by the broker: counted as dropped
  it('should count as dropped the deliveries pending on a channel that closes', async () => {
    const channel = await started();
    channel.deliver(delivery([malware]));
    channel.deliver(delivery([malware]));
    expect(gauge('opencti_dry_intake_pending_messages')).toEqual(1);
    channel.emit('close');
    // The pending one is forgotten at the close, not left to the loop: counted at once, once
    expect(counted('opencti_dry_intake_messages')).toEqual([[1, { rung: 'ack', result: 'dropped' }]]);
    expect(gauge('opencti_dry_intake_pending_messages')).toEqual(0);
    await wait(20);
    expect(channel.ack).not.toHaveBeenCalled();
    expect(counted('opencti_dry_intake_messages')).toEqual([[1, { rung: 'ack', result: 'dropped' }], [1, { rung: 'ack', result: 'dropped' }]]);
  });
  it('should consume each queue once, on a channel of its own, one message at a time across queues', async () => {
    vi.mocked(connectorsForWorker).mockResolvedValueOnce([{ config: { push: 'push_a' } }, { config: { push: 'push_b' } }, { config: { push: 'push_a' } }] as any);
    await started();
    const [a, b] = connection.channels;
    expect(connection.channels).toHaveLength(2);
    expect([a.consume.mock.calls[0][0], b.consume.mock.calls[0][0]]).toEqual(['push_a', 'push_b']);
    expect(gauge('opencti_dry_intake_queues')).toEqual(2);
    const [first, second] = [delivery([malware]), delivery([malware])];
    a.deliver(first);
    b.deliver(second);
    // One loop for all the queues: the second waits while the first is handled
    expect(gauge('opencti_dry_intake_pending_messages')).toEqual(1);
    await wait(20);
    expect(a.ack.mock.calls).toEqual([[first]]);
    expect(b.ack.mock.calls).toEqual([[second]]);
    // A queue that stops leaves the other consumed
    a.emit('close');
    expect(gauge('opencti_dry_intake_queues')).toEqual(1);
    const third = delivery([malware]);
    b.deliver(third);
    await wait(20);
    expect(b.ack.mock.calls).toEqual([[second], [third]]);
  });
  it('should measure the window from the first start to the last answer', async () => {
    const before = Date.now() / 1000;
    const channel = await started();
    expect(gauge('opencti_dry_intake_first_start_timestamp_seconds')).toBeUndefined();
    channel.deliver(delivery([malware]));
    await wait(20);
    const firstStart = gauge('opencti_dry_intake_first_start_timestamp_seconds') as number;
    const lastAck = gauge('opencti_dry_intake_last_ack_timestamp_seconds') as number;
    expect(firstStart).toBeGreaterThanOrEqual(before);
    expect(lastAck).toBeGreaterThanOrEqual(firstStart);
    expect(lastAck).toBeLessThanOrEqual(Date.now() / 1000);
    expect(gauge('opencti_dry_intake_cpu_seconds')).toBeGreaterThanOrEqual(0);
    expect(gauge('opencti_dry_intake_rss_max_bytes')).toBeGreaterThan(0);
    channel.deliver(delivery([malware]));
    await wait(20);
    expect(gauge('opencti_dry_intake_first_start_timestamp_seconds')).toEqual(firstStart);
    expect(gauge('opencti_dry_intake_last_ack_timestamp_seconds')).toBeGreaterThanOrEqual(lastAck);
  });
  it('should close a channel whose consumption the broker cancelled', async () => {
    const channel = await started();
    channel.deliver(null);
    expect(channel.close).toHaveBeenCalledTimes(1);
    expect(gauge('opencti_dry_intake_queues')).toEqual(0);
  });
  it('should validate against the schema at the validate rung only', async () => {
    // The String scalar refuses a number: refused (pycti's ValueError) with the schema, transformed without
    const unnamed = { ...malware, name: 12 };
    const mapped = await started({ rung: 'map' });
    mapped.deliver(delivery([unnamed]));
    await wait(50);
    expect(counted('opencti_dry_intake_object_outcomes')).toEqual([[1, { rung: 'map', outcome: 'transformed' }]]);
    await manager?.shutdown();
    connection = new FakeConnection();
    const validated = await started({ rung: 'validate' });
    validated.deliver(delivery([unnamed]));
    await wait(50);
    expect(counted('opencti_dry_intake_object_outcomes')).toEqual([[1, { rung: 'validate', outcome: 'ValueError' }]]);
  }, 60000);
  it('should connect only after the start delay', async () => {
    vi.useFakeTimers();
    manager = initDryIntakeManager({ ...options, startDelayS: 5 });
    await manager.start();
    await vi.advanceTimersByTimeAsync(4999);
    expect(amqp.connect).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(amqp.connect).toHaveBeenCalledTimes(1);
  });
  it('should not connect when the platform stops before the start delay', async () => {
    vi.useFakeTimers();
    manager = initDryIntakeManager({ ...options, startDelayS: 5 });
    await manager.start();
    await manager.shutdown();
    await vi.advanceTimersByTimeAsync(6000);
    expect(amqp.connect).not.toHaveBeenCalled();
  });
  it('should close the connection at shutdown, and handle nothing after', async () => {
    const channel = await started();
    await manager?.shutdown();
    expect(connection.close).toHaveBeenCalledTimes(1);
    channel.deliver(delivery([malware]));
    await wait(20);
    expect(channel.ack).not.toHaveBeenCalled();
    expect(counted('opencti_dry_intake_messages')).toEqual([]);
  });
  it('should reconnect after a lost connection, and consume again', async () => {
    await started();
    vi.useFakeTimers();
    const lost = connection;
    connection = new FakeConnection();
    lost.lose();
    await vi.advanceTimersByTimeAsync(9999);
    expect(amqp.connect).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(amqp.connect).toHaveBeenCalledTimes(2);
    expect(connection.channels).toHaveLength(1);
    expect(connection.channels[0].consume.mock.calls[0][0]).toEqual('push_a');
  });
  // The connection lost while a message is handled and another waits: both are redelivered
  it('should drop the deliveries of a lost connection, then consume again', async () => {
    const channel = await started();
    channel.deliver(delivery([malware]));
    channel.deliver(delivery([malware]));
    vi.useFakeTimers();
    const lost = connection;
    connection = new FakeConnection();
    lost.lose();
    expect(gauge('opencti_dry_intake_queues')).toEqual(0);
    expect(gauge('opencti_dry_intake_pending_messages')).toEqual(0);
    await vi.advanceTimersByTimeAsync(100);
    expect([...channel.ack.mock.calls, ...channel.nack.mock.calls]).toEqual([]);
    expect(counted('opencti_dry_intake_messages')).toEqual([[1, { rung: 'ack', result: 'dropped' }], [1, { rung: 'ack', result: 'dropped' }]]);
    await vi.advanceTimersByTimeAsync(10000);
    expect(amqp.connect).toHaveBeenCalledTimes(2);
    expect(gauge('opencti_dry_intake_queues')).toEqual(1);
    const again = connection.channels[0];
    const message = delivery([malware]);
    again.deliver(message);
    await vi.advanceTimersByTimeAsync(100);
    expect(again.ack.mock.calls).toEqual([[message]]);
  });
  it('should not reconnect when the platform stops during the retry delay', async () => {
    await started();
    vi.useFakeTimers();
    connection.lose();
    await vi.advanceTimersByTimeAsync(5000);
    await manager?.shutdown();
    await vi.advanceTimersByTimeAsync(20000);
    expect(amqp.connect).toHaveBeenCalledTimes(1);
  });
  it('should retry a connection the broker refuses', async () => {
    vi.useFakeTimers();
    const connect = (_uri: unknown, _options: unknown, callback: (error: unknown, opened: FakeConnection) => void) => callback(new Error('refused'), connection);
    vi.mocked(amqp.connect).mockImplementationOnce(connect as any);
    manager = initDryIntakeManager(options);
    await manager.start();
    await vi.advanceTimersByTimeAsync(0);
    expect(amqp.connect).toHaveBeenCalledTimes(1);
    expect(connection.channels).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(10000);
    expect(amqp.connect).toHaveBeenCalledTimes(2);
    expect(connection.channels).toHaveLength(1);
  });
  it('should neither reconnect when the platform stops, nor keep a connection opened while it stops', async () => {
    await started();
    vi.useFakeTimers();
    await manager?.shutdown();
    connection.emit('close');
    await vi.advanceTimersByTimeAsync(20000);
    expect(amqp.connect).toHaveBeenCalledTimes(1);
    // A connection the broker opens once the platform stops is closed at once
    let opened: (error: unknown, opened: FakeConnection) => void = () => {};
    vi.mocked(amqp.connect).mockImplementationOnce(((_uri: unknown, _options: unknown, callback: typeof opened) => {
      opened = callback;
    }) as any);
    manager = initDryIntakeManager(options);
    await manager.start();
    await vi.advanceTimersByTimeAsync(0);
    await manager.shutdown();
    const late = new FakeConnection();
    opened(null, late);
    expect(late.close).toHaveBeenCalledTimes(1);
    expect(late.channels).toHaveLength(0);
  });
});
