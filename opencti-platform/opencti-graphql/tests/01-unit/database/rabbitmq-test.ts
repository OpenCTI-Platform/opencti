import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Controllable in-memory amqplib so the persistent-publisher tests below can
// drive publish failures, forced reconnections and stale event handlers without
// a real broker. Everything lives in vi.hoisted so the amqplib mock factory
// (hoisted above the imports) and the tests share the same state.
const amqpFake = vi.hoisted(() => {
  type Handlers = Record<string, (...args: any[]) => void>;

  const state = {
    connections: [] as any[],
    // Queue of publish outcomes consumed in order: null = confirmed, an Error =
    // broker nack (confirm callback rejects), 'THROW' = synchronous publish throw.
    publishOutcomes: [] as Array<Error | null | 'THROW'>,
    publishCallCount: 0,
  };

  const makeChannel = () => {
    const handlers: Handlers = {};
    const channel: any = {
      __handlers: handlers,
      on: (event: string, h: (...args: any[]) => void) => {
        handlers[event] = h;
      },
      once: (event: string, h: (...args: any[]) => void) => {
        handlers[event] = h;
      },
      publish: (_exchange: string, _routingKey: string, _content: Buffer, _options: unknown, cb: (err?: Error | null) => void) => {
        state.publishCallCount += 1;
        const outcome = state.publishOutcomes.length > 0 ? state.publishOutcomes.shift() : null;
        if (outcome === 'THROW') {
          throw new Error('synchronous publish failure');
        }
        cb(outcome ?? null);
        return true; // canContinue (no backpressure)
      },
      close: () => { /* no-op for channels */ },
      emit: (event: string, ...args: any[]) => handlers[event]?.(...args),
    };
    return channel;
  };

  const makeConn = () => {
    const handlers: Handlers = {};
    const channel = makeChannel();
    const conn: any = {
      __handlers: handlers,
      __channel: channel,
      closeCount: 0,
      on: (event: string, h: (...args: any[]) => void) => {
        handlers[event] = h;
      },
      createConfirmChannel: (cb: (err: Error | null, channel: any) => void) => cb(null, channel),
      close: () => {
        conn.closeCount += 1;
        // amqplib emits 'close' once the connection is torn down.
        handlers.close?.();
      },
      emit: (event: string, ...args: any[]) => handlers[event]?.(...args),
    };
    state.connections.push(conn);
    return conn;
  };

  const connect = (_uri: string, _opts: unknown, cb: (err: Error | null, conn: any) => void) => cb(null, makeConn());

  const reset = () => {
    state.connections = [];
    state.publishOutcomes = [];
    state.publishCallCount = 0;
  };

  return { state, makeConn, connect, reset };
});

vi.mock('amqplib/callback_api', () => ({
  default: {
    connect: amqpFake.connect,
    credentials: { plain: () => ({}) },
  },
}));

const mockHttpClient = {
  get: vi.fn(),
  delete: vi.fn(),
};

vi.mock('../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(() => mockHttpClient),
}));

vi.mock('../../../src/config/conf', () => ({
  default: { get: vi.fn(() => undefined) },
  booleanConf: vi.fn(() => false),
  configureCA: vi.fn(() => ({})),
  loadCert: vi.fn(),
  logApp: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock('../../../src/config/tracing', () => ({
  telemetry: vi.fn((_ctx: unknown, _user: unknown, _name: unknown, _attrs: unknown, fn: () => unknown) => fn()),
}));

vi.mock('../../../src/database/utils', () => ({
  isEmptyField: vi.fn((v: unknown) => !v),
  RABBIT_QUEUE_PREFIX: 'opencti_',
  wait: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(async () => []),
}));

vi.mock('../../../src/database/raw-file-storage', () => ({
  s3ConnectionConfig: vi.fn(() => ({})),
}));

vi.mock('../../../src/utils/access', () => ({
  SYSTEM_USER: {},
}));

vi.mock('../../../src/schema/internalObject', () => ({
  ENTITY_TYPE_BACKGROUND_TASK: 'Background-Task',
  ENTITY_TYPE_CONNECTOR: 'Connector',
  ENTITY_TYPE_SYNC: 'Sync',
}));

vi.mock('../../../src/modules/playbook/playbook-types', () => ({
  ENTITY_TYPE_PLAYBOOK: 'Playbook',
}));

// Mock LRUCache so the cache never returns stale data between test
vi.mock('lru-cache', () => {
  class FakeLRUCache {
    get() {
      return undefined;
    }

    set() { /* no-op */ }
  }
  return { LRUCache: FakeLRUCache };
});

import { getConnectorQueueSize, metrics } from '../../../src/database/rabbitmq';

describe('rabbitmq: metrics', () => {
  const context = {};
  const user = {};

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return overview, consumers count and filtered platform queues', async () => {
    const overviewData = { rabbitmq_version: '3.12.0', cluster_name: 'test' };
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: overviewData });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 42, consumers: 3 },
            { name: 'opencti_listen_connector-abc', messages: 5, consumers: 0 },
            { name: 'other_queue', messages: 100, consumers: 2 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await metrics(context, user);

    expect(result.overview).toEqual(overviewData);
    expect(result.consumers).toBe(3);
    // Only platform queues (starting with 'opencti_') should be included
    expect(result.queues).toHaveLength(2);
    expect(result.queues.every((q: { name: string }) => q.name.startsWith('opencti_'))).toBe(true);
  });

  it('should return consumers as 0 when no push queues have consumers', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 10, consumers: 0 },
            { name: 'opencti_listen_connector-abc', messages: 5, consumers: 0 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await metrics(context, user);

    expect(result.consumers).toBe(0);
  });

  it('should return empty queues when no platform queues exist', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'some_other_queue', messages: 100, consumers: 5 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await metrics(context, user);

    expect(result.overview).toEqual({ rabbitmq_version: '3.12.0' });
    expect(result.consumers).toBe(0);
    expect(result.queues).toHaveLength(0);
  });

  it('should pass a 5 seconds timeout to the GET requests', async () => {
    mockHttpClient.get.mockImplementation(() => {
      return Promise.resolve({ data: [] });
    });

    await metrics(context, user);

    expect(mockHttpClient.get).toHaveBeenCalledTimes(2);
    expect(mockHttpClient.get).toHaveBeenCalledWith('/api/overview', { timeout: 5000 });
    expect(mockHttpClient.get).toHaveBeenCalledWith(expect.stringContaining('/api/queues'), { timeout: 5000 });
  });

  it('should propagate errors from the HTTP client', async () => {
    mockHttpClient.get.mockRejectedValue(new Error('Connection refused'));

    await expect(metrics(context, user)).rejects.toThrow('Connection refused');
  });
});

describe('rabbitmq: getConnectorQueueSize', () => {
  const context = {};
  const user = {};

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return the message count when exactly one queue matches', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 42, consumers: 1 },
            { name: 'opencti_push_connector-xyz', messages: 10, consumers: 1 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-abc');
    expect(result).toBe(42);
  });

  it('should return 0 when exactly one queue matches but messages is undefined', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', consumers: 1 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-abc');
    expect(result).toBe(0);
  });

  it('should return 0 when no queues match', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-xyz', messages: 10, consumers: 1 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-unknown');
    expect(result).toBe(0);
  });

  it('should return the sum of messages when multiple queues match', async () => {
    mockHttpClient.get.mockImplementation((url: string) => {
      if (url === '/api/overview') {
        return Promise.resolve({ data: { rabbitmq_version: '3.12.0' } });
      }
      if (url.includes('/api/queues')) {
        return Promise.resolve({
          data: [
            { name: 'opencti_push_connector-abc', messages: 10, consumers: 1 },
            { name: 'opencti_listen_connector-abc', messages: 5, consumers: 0 },
          ],
        });
      }
      return Promise.resolve({ data: {} });
    });

    const result = await getConnectorQueueSize(context, user, 'connector-abc');
    expect(result).toBe(15);
  });
});

// ── Persistent publisher: send() retry loop and connection event handlers ────

const EXCHANGE = 'test.exchange';
const ROUTING_KEY = 'test.routing';
const MESSAGE = 'hello';

let publisherLogApp: { info: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn>; debug: ReturnType<typeof vi.fn> };
let send: (exchangeName: string, routingKey: string, message: string) => Promise<boolean>;

// Re-import the (mocked) conf and the module under test against a fresh module
// graph so rabbitmq.js internal connection state is reset between tests.
const loadFreshPublisher = async () => {
  vi.resetModules();
  amqpFake.reset();
  const confModule = await import('../../../src/config/conf');
  publisherLogApp = confModule.logApp as unknown as typeof publisherLogApp;
  const rabbitmq = await import('../../../src/database/rabbitmq');
  send = rabbitmq.send;
};

const warnMessages = () => publisherLogApp.warn.mock.calls.map((c) => String(c[0]));
const errorMessages = () => publisherLogApp.error.mock.calls.map((c) => String(c[0]));
const infoMessages = () => publisherLogApp.info.mock.calls.map((c) => String(c[0]));

describe('rabbitmq persistent publisher: send() retry loop', () => {
  beforeEach(async () => {
    await loadFreshPublisher();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should publish on the first attempt and not log any recovery', async () => {
    const result = await send(EXCHANGE, ROUTING_KEY, MESSAGE);

    expect(result).toBe(true);
    expect(amqpFake.state.publishCallCount).toBe(1);
    expect(infoMessages().some((m) => m.includes('Send recovered'))).toBe(false);
    expect(warnMessages().some((m) => m.includes('Send failed'))).toBe(false);
  });

  it('should retry a transient publish failure and log recovery once', async () => {
    amqpFake.state.publishOutcomes = [new Error('transient nack')];

    const result = await send(EXCHANGE, ROUTING_KEY, MESSAGE);

    expect(result).toBe(true);
    expect(amqpFake.state.publishCallCount).toBe(2);
    expect(warnMessages().some((m) => m.includes('Send failed (attempt 1)'))).toBe(true);
    expect(infoMessages().some((m) => m.includes('Send recovered after 1 failed attempt(s)'))).toBe(true);
    // A single transient failure must not force a reconnection.
    expect(amqpFake.state.connections.every((c) => c.closeCount === 0)).toBe(true);
  });

  it('should force a clean reconnection after repeated failures on a seemingly-open channel', async () => {
    // Channel keeps confirming-nacking while it still looks open: 3 failures then success.
    amqpFake.state.publishOutcomes = [new Error('nack'), new Error('nack'), new Error('nack')];

    const result = await send(EXCHANGE, ROUTING_KEY, MESSAGE);

    expect(result).toBe(true);
    expect(warnMessages().some((m) => m.includes('Forcing publisher reconnection after 3 consecutive send failures'))).toBe(true);
    // The first (zombie) connection must have been torn down by resetPersistentConnection.
    expect(amqpFake.state.connections[0].closeCount).toBeGreaterThan(0);
    // A fresh connection must have been rebuilt.
    expect(amqpFake.state.connections.length).toBeGreaterThan(1);
    expect(infoMessages().some((m) => m.includes('Send recovered'))).toBe(true);
  });

  it('should throttle forced reconnections instead of forcing on every attempt past the threshold', async () => {
    // 7 consecutive failures on a seemingly-open channel, then success.
    amqpFake.state.publishOutcomes = Array.from({ length: 7 }, () => new Error('nack'));

    const result = await send(EXCHANGE, ROUTING_KEY, MESSAGE);

    expect(result).toBe(true);
    const forcing = warnMessages().filter((m) => m.includes('Forcing publisher reconnection'));
    // Throttled to once every SEND_FORCE_RECONNECT_AFTER (3) attempts -> attempts 3 and 6 only,
    // NOT on every attempt past the threshold (which would be attempts 3, 4, 5, 6 and 7).
    expect(forcing).toHaveLength(2);
    expect(forcing.some((m) => m.includes('after 3 consecutive send failures'))).toBe(true);
    expect(forcing.some((m) => m.includes('after 6 consecutive send failures'))).toBe(true);
    expect(forcing.some((m) => m.includes('after 4 consecutive send failures'))).toBe(false);
  });

  it('should wait for background recovery when the channel is lost (publish throws)', async () => {
    amqpFake.state.publishOutcomes = ['THROW'];

    const result = await send(EXCHANGE, ROUTING_KEY, MESSAGE);

    expect(result).toBe(true);
    expect(infoMessages().some((m) => m.includes('Waiting for connection recovery before retry'))).toBe(true);
  });

  it('should escalate to error logging once the warn threshold is exceeded', async () => {
    // 10 consecutive failures then success: the 10th attempt hits the error interval.
    amqpFake.state.publishOutcomes = Array.from({ length: 10 }, () => new Error('persistent nack'));

    const result = await send(EXCHANGE, ROUTING_KEY, MESSAGE);

    expect(result).toBe(true);
    expect(errorMessages().some((m) => m.includes('Send still failing after 10 attempts'))).toBe(true);
  });
});

describe('rabbitmq persistent publisher: connection event handlers', () => {
  beforeEach(async () => {
    await loadFreshPublisher();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should log broker resource alarms on the active connection', async () => {
    await send(EXCHANGE, ROUTING_KEY, MESSAGE);
    const activeConn = amqpFake.state.connections[0];
    publisherLogApp.error.mockClear();
    publisherLogApp.info.mockClear();

    activeConn.emit('blocked', 'low on memory');
    activeConn.emit('unblocked');
    activeConn.emit('error', new Error('connection boom'));

    expect(errorMessages().some((m) => m.includes('BLOCKED by broker resource alarm'))).toBe(true);
    expect(infoMessages().some((m) => m.includes('unblocked by broker'))).toBe(true);
    expect(errorMessages().some((m) => m.includes('Persistent connection error'))).toBe(true);
  });

  it('should ignore stale connection events after the connection has been replaced', async () => {
    await send(EXCHANGE, ROUTING_KEY, MESSAGE);
    const staleConn = amqpFake.state.connections[0];

    // Emitting close on the active connection triggers a background reconnect,
    // so a fresh connection becomes the active one and staleConn becomes stale.
    staleConn.emit('close');
    expect(amqpFake.state.connections.length).toBeGreaterThan(1);

    publisherLogApp.error.mockClear();
    publisherLogApp.info.mockClear();
    publisherLogApp.warn.mockClear();

    // Late events from the leaked/old connection must be ignored entirely.
    staleConn.emit('blocked', 'late alarm');
    staleConn.emit('unblocked');
    staleConn.emit('error', new Error('late error'));
    staleConn.emit('close');

    expect(errorMessages().some((m) => m.includes('BLOCKED by broker resource alarm'))).toBe(false);
    expect(infoMessages().some((m) => m.includes('unblocked by broker'))).toBe(false);
    expect(errorMessages().some((m) => m.includes('Persistent connection error'))).toBe(false);
    expect(warnMessages().some((m) => m.includes('Persistent connection closed'))).toBe(false);
  });

  it('should tear down the connection when the active channel errors', async () => {
    await send(EXCHANGE, ROUTING_KEY, MESSAGE);
    const conn = amqpFake.state.connections[0];

    conn.__channel.emit('error', new Error('channel boom'));

    expect(errorMessages().some((m) => m.includes('Persistent channel error'))).toBe(true);
    expect(conn.closeCount).toBeGreaterThan(0);
  });

  it('should tear down the connection when the active channel closes', async () => {
    await send(EXCHANGE, ROUTING_KEY, MESSAGE);
    const conn = amqpFake.state.connections[0];

    conn.__channel.emit('close');

    expect(warnMessages().some((m) => m.includes('Persistent channel closed'))).toBe(true);
    expect(conn.closeCount).toBeGreaterThan(0);
  });

  it('should ignore stale channel error and close events after the channel has been replaced', async () => {
    await send(EXCHANGE, ROUTING_KEY, MESSAGE);
    const staleChannel = amqpFake.state.connections[0].__channel;

    // Closing the active channel rebuilds a fresh connection/channel, so the
    // original channel becomes stale.
    staleChannel.emit('close');
    expect(amqpFake.state.connections.length).toBeGreaterThan(1);

    publisherLogApp.error.mockClear();
    publisherLogApp.warn.mockClear();

    staleChannel.emit('error', new Error('late channel error'));
    staleChannel.emit('close');

    expect(errorMessages().some((m) => m.includes('Persistent channel error'))).toBe(false);
    expect(warnMessages().some((m) => m.includes('Persistent channel closed'))).toBe(false);
  });
});
