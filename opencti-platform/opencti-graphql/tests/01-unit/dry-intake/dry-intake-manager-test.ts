import { beforeEach, describe, expect, it, vi } from 'vitest';
import amqp from 'amqplib/callback_api';
import { connectorsForWorker } from '../../../src/modules/connector/connector-domain';
import createSchema from '../../../src/graphql/schema';
import { createDryDrain, type DryAnswer } from '../../../src/intake/dry-intake/dry-intake-drain';
import { type DryMessageResult, emptyResult } from '../../../src/intake/dry-intake/dry-intake-message';
import { createDryWindow, dryIntakeOptionsError, type DryIntakeOptions, initDryIntakeManager, recordResult } from '../../../src/intake/dry-intake/dry-intake-manager';

vi.mock('amqplib/callback_api', () => ({ default: { connect: vi.fn() } }));
vi.mock('../../../src/database/rabbitmq', () => ({ rabbitmqUri: () => 'amqp://localhost', rabbitmqConnectionOptions: () => ({}) }));
vi.mock('../../../src/modules/connector/connector-domain', () => ({ connectorsForWorker: vi.fn(async () => [{ config: { push: 'push_a' } }]) }));
vi.mock('../../../src/graphql/schema', () => ({ default: vi.fn(() => null) }));

interface Message { id: number }
const channel = () => ({ ack: vi.fn<(message: Message) => void>(), nack: vi.fn<(message: Message, allUpTo?: boolean, requeue?: boolean) => void>() });
const wait = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});
const acked = (): DryMessageResult => emptyResult();
const nacked = (): DryMessageResult => ({ ...emptyResult(), ack: false, failedStage: 'decode' });

const drainWith = (
  handle: (body: string) => Promise<DryMessageResult>,
  isOpen: (c: unknown) => boolean = () => true,
  hooks: { onStart?: () => void; onAnswer?: () => void; stopping?: () => boolean } = {},
) => {
  const answers: { id: number; answer: DryAnswer; defect: boolean }[] = [];
  const errors: unknown[] = [];
  const drain = createDryDrain<Message>({
    body: (message) => String(message.id),
    handle,
    isOpen,
    stopping: hooks.stopping ?? (() => false),
    onStart: hooks.onStart ?? (() => {}),
    onAnswer: (result, answer) => {
      answers.push({ id: result.objects, answer, defect: result.defect });
      hooks.onAnswer?.();
    },
    onError: (cause) => errors.push(cause),
  });
  return { drain, answers, errors };
};
const ids = (answers: { id: number; answer: DryAnswer }[]) => answers.map(({ id, answer }) => ({ id, answer }));

describe('Dry intake drain: one message at a time, answered once on its own channel', () => {
  it('should ack each delivery once, on the channel it came on', async () => {
    const [a, b] = [channel(), channel()];
    const { drain } = drainWith(async () => acked());
    await Promise.all([drain.push({ id: 1 }, a), drain.push({ id: 2 }, b)]);
    expect(a.ack.mock.calls).toEqual([[{ id: 1 }]]);
    expect(b.ack.mock.calls).toEqual([[{ id: 2 }]]);
    expect([...a.nack.mock.calls, ...b.nack.mock.calls]).toEqual([]);
  });
  it('should nack, without requeue, a message the handling refuses', async () => {
    const a = channel();
    await drainWith(async () => nacked()).drain.push({ id: 1 }, a);
    expect(a.nack.mock.calls).toEqual([[{ id: 1 }, false, false]]);
    expect(a.ack).not.toHaveBeenCalled();
  });
  it('should not answer on a closed channel, and report the message as dropped', async () => {
    const [closed, open] = [channel(), channel()];
    const { drain, answers } = drainWith(async (body) => ({ ...acked(), objects: Number(body) }), (c) => c === open);
    await Promise.all([drain.push({ id: 1 }, closed), drain.push({ id: 2 }, open)]);
    expect([...closed.ack.mock.calls, ...closed.nack.mock.calls]).toEqual([]);
    expect(ids(answers)).toEqual([{ id: 1, answer: 'dropped' }, { id: 2, answer: 'acked' }]);
  });
  it('should forget the pending messages of a closed channel', async () => {
    const [a, b] = [channel(), channel()];
    let release: () => void = () => {};
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { drain } = drainWith(async () => {
      await released;
      return acked();
    });
    const done = Promise.all([drain.push({ id: 1 }, a), drain.push({ id: 2 }, b), drain.push({ id: 3 }, a), drain.push({ id: 4 }, b), drain.push({ id: 5 }, a)]);
    // Only those of the closed channel, the others kept in order
    expect(drain.forget(b)).toEqual(2);
    expect(drain.pending()).toEqual(2);
    release();
    await done;
    await wait(10);
    expect(b.ack).not.toHaveBeenCalled();
    expect(a.ack.mock.calls).toEqual([[{ id: 1 }], [{ id: 3 }], [{ id: 5 }]]);
  });
  // Messages in flight = queues x prefetch, up to 65535 each: beyond the engine's argument limit
  it('should forget the pending messages of a closed channel among a large number kept', async () => {
    const [a, b] = [channel(), channel()];
    const { drain } = drainWith(() => new Promise<DryMessageResult>(() => {}));
    const pushed = [drain.push({ id: 0 }, a)];
    for (let id = 1; id <= 200000; id += 1) {
      pushed.push(drain.push({ id }, id % 1000 === 0 ? b : a));
    }
    expect(drain.forget(b)).toEqual(200);
    expect(drain.pending()).toEqual(199800);
  });
  it('should handle strictly one message at a time, in order of arrival', async () => {
    let active = 0;
    let maxActive = 0;
    const order: string[] = [];
    const { drain } = drainWith(async (body) => {
      active += 1;
      maxActive = Math.max(maxActive, active);
      order.push(body);
      await wait(5);
      active -= 1;
      return acked();
    });
    const a = channel();
    await Promise.all([drain.push({ id: 1 }, a), drain.push({ id: 2 }, a), drain.push({ id: 3 }, a)]);
    expect(maxActive).toEqual(1);
    expect(order).toEqual(['1', '2', '3']);
  });
  it('should go on after an ack or a handling that throws', async () => {
    const [failing, b] = [channel(), channel()];
    failing.ack.mockImplementation(() => {
      throw new Error('Channel closing');
    });
    const { drain, answers, errors } = drainWith(async (body) => {
      if (body === '2') throw new TypeError('handling');
      return { ...acked(), objects: Number(body) };
    });
    await Promise.all([drain.push({ id: 1 }, failing), drain.push({ id: 2 }, b), drain.push({ id: 3 }, b)]);
    // 1: the ack threw, dropped; 2: the handling threw, a defect nacked; 3: acked
    expect(answers).toEqual([{ id: 1, answer: 'dropped', defect: false }, { id: 0, answer: 'nacked', defect: true }, { id: 3, answer: 'acked', defect: false }]);
    // The ack that threw is not followed by a nack: one answer at most per delivery
    expect(failing.nack).not.toHaveBeenCalled();
    expect(b.nack.mock.calls).toEqual([[{ id: 2 }, false, false]]);
    expect(b.ack.mock.calls).toEqual([[{ id: 3 }]]);
    expect(errors).toHaveLength(2);
    // The loop is not stuck: a later delivery is handled
    await drain.push({ id: 4 }, b);
    expect(b.ack.mock.calls).toEqual([[{ id: 3 }], [{ id: 4 }]]);
  });
});

describe('Dry intake drain: a failure outside the handling does not stop it', () => {
  // Three deliveries in flight: a hook that throws on the second neither leaves it unanswered nor
  // strands the third until a new delivery comes
  it('should answer every delivery once when the start hook throws', async () => {
    const a = channel();
    let starts = 0;
    const { drain, errors } = drainWith(async (body) => ({ ...acked(), objects: Number(body) }), () => true, {
      onStart: () => {
        starts += 1;
        if (starts === 2) throw new Error('start hook');
      },
    });
    await Promise.all([drain.push({ id: 1 }, a), drain.push({ id: 2 }, a), drain.push({ id: 3 }, a)]);
    await wait(10);
    expect(a.ack.mock.calls).toEqual([[{ id: 1 }], [{ id: 3 }]]);
    expect(a.nack.mock.calls).toEqual([[{ id: 2 }, false, false]]);
    expect(drain.pending()).toEqual(0);
    expect(errors).toHaveLength(1);
  });
  it('should go on when the answer hook throws', async () => {
    const a = channel();
    let answered = 0;
    const { drain, errors } = drainWith(async () => acked(), () => true, {
      onAnswer: () => {
        answered += 1;
        if (answered === 2) throw new Error('answer hook');
      },
    });
    await Promise.all([drain.push({ id: 1 }, a), drain.push({ id: 2 }, a), drain.push({ id: 3 }, a)]);
    await wait(10);
    expect(a.ack.mock.calls).toEqual([[{ id: 1 }], [{ id: 2 }], [{ id: 3 }]]);
    expect(a.nack).not.toHaveBeenCalled();
    expect(drain.pending()).toEqual(0);
    expect(errors).toHaveLength(1);
  });
  // Even a failure of the error hook does not leave the later deliveries waiting for a new one
  it('should go on with the pending deliveries when the error hook throws too', async () => {
    const a = channel();
    let starts = 0;
    const drain = createDryDrain<Message>({
      body: (message) => String(message.id),
      handle: async () => acked(),
      isOpen: () => true,
      stopping: () => false,
      // The second message, once the loop has awaited: nothing else would restart it
      onStart: () => {
        starts += 1;
        if (starts === 2) throw new Error('start hook');
      },
      onAnswer: () => {},
      onError: () => {
        throw new Error('error hook');
      },
    });
    await Promise.allSettled([drain.push({ id: 1 }, a), drain.push({ id: 2 }, a), drain.push({ id: 3 }, a)]);
    await wait(20);
    expect(a.ack.mock.calls).toEqual([[{ id: 1 }], [{ id: 3 }]]);
    // The second is answered all the same: a delivery left unanswered holds a prefetch slot
    expect(a.nack.mock.calls).toEqual([[{ id: 2 }, false, false]]);
    expect(drain.pending()).toEqual(0);
  });
  it('should go on when the error hook throws on an ack that throws', async () => {
    const [failing, b] = [channel(), channel()];
    failing.ack.mockImplementation(() => {
      throw new Error('Channel closing');
    });
    const answers: DryAnswer[] = [];
    const drain = createDryDrain<Message>({
      body: (message) => String(message.id),
      handle: async () => acked(),
      isOpen: () => true,
      stopping: () => false,
      onStart: () => {},
      onAnswer: (_, answer) => answers.push(answer),
      onError: () => {
        throw new Error('error hook');
      },
    });
    await Promise.allSettled([drain.push({ id: 1 }, failing), drain.push({ id: 2 }, b)]);
    await wait(20);
    expect(answers).toEqual(['dropped', 'acked']);
    expect(b.ack.mock.calls).toEqual([[{ id: 2 }]]);
    expect(drain.pending()).toEqual(0);
  });
  it('should stop handling when the platform stops', async () => {
    const a = channel();
    let stopping = false;
    const { drain } = drainWith(async () => {
      stopping = true;
      return acked();
    }, () => true, { stopping: () => stopping });
    await Promise.all([drain.push({ id: 1 }, a), drain.push({ id: 2 }, a)]);
    await wait(10);
    expect(a.ack.mock.calls).toEqual([[{ id: 1 }]]);
    expect(drain.pending()).toEqual(1);
  });
});

describe('Dry intake metrics: what each answer counts', () => {
  const fakeMetrics = () => {
    const counter = () => ({ add: vi.fn() });
    const histogram = () => ({ record: vi.fn() });
    return {
      messages: counter(), defects: counter(), objects: counter(), parts: counter(), operations: counter(), outcomes: counter(), stage: histogram(), messageObjects: histogram(),
    };
  };
  const result = { ...emptyResult(), defect: true, objects: 3, parts: 2, operations: 5, outcomes: { transformed: 2, set_aside: 1 }, timings: { decode: 0.1, map: 0.2 } };
  // A dropped message is redelivered and counted then: only the drop is counted
  it('should count only the drop of a dropped message', () => {
    const metrics = fakeMetrics();
    recordResult(metrics as any, 'map', result, 'dropped');
    expect(metrics.messages.add.mock.calls).toEqual([[1, { rung: 'map', result: 'dropped' }]]);
    const others = [metrics.defects.add, metrics.objects.add, metrics.parts.add, metrics.operations.add, metrics.outcomes.add, metrics.stage.record, metrics.messageObjects.record];
    expect(others.map((fn) => fn.mock.calls.length)).toEqual([0, 0, 0, 0, 0, 0, 0]);
  });
  it('should count defects, objects, parts, operations, outcomes and stages of an answered message', () => {
    const metrics = fakeMetrics();
    recordResult(metrics as any, 'map', result, 'nacked');
    expect(metrics.messages.add.mock.calls).toEqual([[1, { rung: 'map', result: 'nacked' }]]);
    expect(metrics.defects.add.mock.calls).toEqual([[1, { rung: 'map' }]]);
    expect(metrics.objects.add.mock.calls).toEqual([[3, { rung: 'map' }]]);
    expect(metrics.parts.add.mock.calls).toEqual([[2, { rung: 'map' }]]);
    expect(metrics.operations.add.mock.calls).toEqual([[5, { rung: 'map' }]]);
    expect(metrics.outcomes.add.mock.calls).toEqual([[2, { rung: 'map', outcome: 'transformed' }], [1, { rung: 'map', outcome: 'set_aside' }]]);
    expect(metrics.stage.record.mock.calls).toEqual([[0.1, { stage: 'decode' }], [0.2, { stage: 'map' }]]);
    expect(metrics.messageObjects.record.mock.calls).toEqual([[3, { rung: 'map' }]]);
  });
  it('should not record the objects of a message without objects (ack rung, refused message)', () => {
    const metrics = fakeMetrics();
    recordResult(metrics as any, 'ack', emptyResult(), 'acked');
    recordResult(metrics as any, 'map', { ...emptyResult(), ack: false, failedStage: 'decode' }, 'nacked');
    expect(metrics.messageObjects.record).not.toHaveBeenCalled();
    expect(metrics.defects.add).not.toHaveBeenCalled();
  });
});

describe('Dry intake window: from the start of the first message to the last answer', () => {
  const probes = () => {
    const clock = { now: 100, cpu: 0, rss: 10 };
    // Only the 99th percentile is 20 ms
    const lag = { reset: vi.fn(), percentile: vi.fn((percentile: number) => (percentile === 99 ? 2e7 : 9e9)), max: 5e7 };
    const measure = createDryWindow({
      now: () => clock.now,
      cpuUsage: (previous) => ({ user: clock.cpu - (previous ? previous.user : 0), system: 0 }),
      rss: () => clock.rss,
      lag,
    });
    return { clock, lag, measure };
  };
  it('should start at the first message only, and end at the last answer', () => {
    const { clock, lag, measure } = probes();
    clock.cpu = 1e6;
    measure.start();
    clock.now = 101;
    clock.cpu = 3e6;
    expect(measure.answer('acked')).toEqual(1);
    clock.now = 103;
    measure.start();
    clock.now = 104;
    clock.rss = 30;
    clock.cpu = 5e6;
    expect(measure.answer('nacked')).toEqual(1);
    expect(measure.window).toMatchObject({ firstStart: 100, lastAck: 104, cpuSeconds: 4, rssMax: 30, lagP99: 0.02, lagMax: 0.05 });
    // The lag is reset at the first start only: it covers the whole window
    expect(lag.reset).toHaveBeenCalledTimes(1);
  });
  it('should keep the highest RSS seen at an answer, not the last one', () => {
    const { clock, measure } = probes();
    measure.start();
    clock.rss = 30;
    measure.answer('acked');
    measure.start();
    clock.rss = 20;
    measure.answer('acked');
    expect(measure.window.rssMax).toEqual(30);
  });
  it('should not end the window, nor take a snapshot, at a dropped answer', () => {
    const { clock, measure } = probes();
    measure.start();
    clock.now = 101;
    measure.answer('acked');
    clock.now = 102;
    measure.start();
    clock.now = 110;
    clock.rss = 99;
    expect(measure.answer('dropped')).toEqual(8);
    expect(measure.window).toMatchObject({ firstStart: 100, lastAck: 101, rssMax: 10 });
  });
});

describe('Dry intake manager: refuses to start on a wrong configuration', () => {
  const valid: DryIntakeOptions = { rung: 'validate', prefetch: 10, startDelayS: 0, metricsEnabled: true };
  beforeEach(() => {
    vi.mocked(connectorsForWorker).mockClear();
    vi.mocked(createSchema).mockClear();
    vi.mocked(amqp.connect).mockClear();
  });
  it('should accept a valid configuration', () => {
    expect(dryIntakeOptionsError(valid)).toBeNull();
    expect(dryIntakeOptionsError({ ...valid, prefetch: 1, startDelayS: 2.5 })).toBeNull();
    expect(dryIntakeOptionsError({ ...valid, prefetch: 65535, startDelayS: (2 ** 31 - 1) / 1000 })).toBeNull();
  });
  it.each([
    ['an empty rung', { rung: '' }, 'rung'],
    ['an unknown rung', { rung: 'foo' }, 'rung'],
    ['prefetch 0 (no limit in AMQP)', { prefetch: 0 }, 'prefetch'],
    ['a fractional prefetch', { prefetch: 1.5 }, 'prefetch'],
    ['a prefetch given as text', { prefetch: '10' }, 'prefetch'],
    ['a prefetch above the AMQP limit', { prefetch: 65536 }, 'prefetch'],
    ['a negative start delay', { startDelayS: -1 }, 'start_delay_s'],
    ['a start delay given as text', { startDelayS: '5' }, 'start_delay_s'],
    ['a start delay that is not a number', { startDelayS: NaN }, 'start_delay_s'],
    ['an infinite start delay', { startDelayS: Infinity }, 'start_delay_s'],
    ['a start delay above the timer limit', { startDelayS: 2 ** 31 / 1000 }, 'start_delay_s'],
    ['metrics disabled', { metricsEnabled: false }, 'metrics'],
  ])('should refuse %s', (_, change, key) => {
    expect(dryIntakeOptionsError({ ...valid, ...change })).toContain(key);
  });
  it.each([['an empty rung', { rung: '' }], ['an unknown rung', { rung: 'foo' }], ['metrics disabled', { metricsEnabled: false }], ['prefetch 0', { prefetch: 0 }]])(
    'should neither consume nor build the schema with %s',
    async (_, change) => {
      const manager = initDryIntakeManager({ ...valid, ...change });
      await expect(manager.start()).resolves.toBe(false);
      await wait(20);
      expect(connectorsForWorker).not.toHaveBeenCalled();
      expect(createSchema).not.toHaveBeenCalled();
      expect(amqp.connect).not.toHaveBeenCalled();
      await manager.shutdown();
    },
  );
  it('should list the queues, build the schema and connect with a valid configuration', async () => {
    const manager = initDryIntakeManager(valid);
    await expect(manager.start()).resolves.toBe(true);
    await wait(20);
    expect(connectorsForWorker).toHaveBeenCalledTimes(1);
    expect(createSchema).toHaveBeenCalledTimes(1);
    expect(amqp.connect).toHaveBeenCalledTimes(1);
    await manager.shutdown();
  });
});
