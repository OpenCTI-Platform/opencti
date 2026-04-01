import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

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

import { getConnectorQueueSize } from '../../../src/database/rabbitmq';

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
