import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// A fake redis client: the hashes of the platforms' loads in memory, nothing is connected.
const { hashes, mockClient } = vi.hoisted(() => {
  const store = new Map<string, Map<string, string>>();
  const hash = (key: string) => {
    if (!store.has(key)) store.set(key, new Map());
    return store.get(key) as Map<string, string>;
  };
  const hset = (key: string, field: string, value: string) => {
    hash(key).set(field, value);
    return 1;
  };
  const hdel = (key: string, ...fields: string[]) => fields.filter((field) => hash(key).delete(field)).length;
  // A transaction: its commands queued, applied together on exec
  const multi = () => {
    const queued: (() => number)[] = [];
    const tx = {
      hset: (key: string, field: string, value: string) => {
        queued.push(() => hset(key, field, value));
        return tx;
      },
      hdel: (key: string, ...fields: string[]) => {
        queued.push(() => hdel(key, ...fields));
        return tx;
      },
      exec: async () => queued.map((command): [null, number] => [null, command()]),
    };
    return tx;
  };
  const client = {
    on: vi.fn(),
    disconnect: vi.fn(),
    multi: vi.fn(multi),
    hset: vi.fn(async (key: string, field: string, value: string) => hset(key, field, value)),
    hgetall: vi.fn(async (key: string) => Object.fromEntries(hash(key))),
    hdel: vi.fn(async (key: string, ...fields: string[]) => hdel(key, ...fields)),
  };
  return { hashes: store, mockClient: client };
});

vi.mock('ioredis', () => ({
  Redis: vi.fn(function RedisMock() {
    return mockClient;
  }),
  Cluster: vi.fn(function ClusterMock() {
    return mockClient;
  }),
}));
vi.mock('graphql-redis-subscriptions', () => ({
  RedisPubSub: vi.fn(function RedisPubSubMock() {
    return {};
  }),
}));
vi.mock('../../../src/config/credentials', () => ({
  enrichWithRemoteCredentials: vi.fn(async (_service: string, auth: unknown) => auth),
}));
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  const overrides: Record<string, unknown> = { 'redis:mode': 'single', 'redis:ca': [], 'redis:hostname': 'redis.example.test', 'redis:port': 6379, 'redis:database': 0 };
  return {
    ...actual,
    default: { ...actual.default, get: (key: string) => (key in overrides ? overrides[key] : actual.default.get(key)) },
  };
});

import { initializeRedisClients, redisQueueLeaseStore } from '../../../src/database/redis';

const BYTES = '{intake}:nodes:bytes';
// read by the platforms of the previous version (message counts)
const LEGACY = '{intake}:nodes';
const TTL = 30000;

describe('redis queue lease store: the loads of the platforms', () => {
  beforeAll(async () => {
    await initializeRedisClients();
  });

  beforeEach(() => {
    hashes.clear();
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(1_000_000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should publish its load in bytes, and its message count for the previous version, in one transaction', async () => {
    await redisQueueLeaseStore.publishBacklog('a:1', 8400, 18);
    expect(hashes.get(BYTES)?.get('a:1')).toBe('8400:1000000');
    expect(hashes.get(LEGACY)?.get('a:1')).toBe('18:1000000');
    expect(mockClient.multi).toHaveBeenCalledTimes(1);
    expect(mockClient.hset).not.toHaveBeenCalled();
  });

  it('should read the live platforms, those of the previous version with a load unknown', async () => {
    await redisQueueLeaseStore.publishBacklog('a:1', 8400, 18);
    hashes.get(LEGACY)?.set('old:1', '40:1000000'); // previous version: message counts only
    expect(await redisQueueLeaseStore.liveBacklogs(TTL)).toEqual(new Map([['a:1', 8400], ['old:1', null]]));
  });

  it('should count out a platform silent for a TTL, and remove the ones silent for ten', async () => {
    await redisQueueLeaseStore.publishBacklog('dead:1', 100, 1);
    vi.setSystemTime(1_000_000 + 8 * TTL);
    await redisQueueLeaseStore.publishBacklog('silent:1', 200, 2);
    vi.setSystemTime(1_000_000 + 10 * TTL + 1);
    await redisQueueLeaseStore.publishBacklog('a:1', 300, 3);
    expect(await redisQueueLeaseStore.liveBacklogs(TTL)).toEqual(new Map([['a:1', 300]]));
    // dead for ten TTLs: removed from both hashes; silent for one: kept
    expect(hashes.get(BYTES)?.has('dead:1')).toBe(false);
    expect(hashes.get(LEGACY)?.has('dead:1')).toBe(false);
    expect(hashes.get(BYTES)?.has('silent:1')).toBe(true);
    expect(hashes.get(LEGACY)?.has('silent:1')).toBe(true);
  });

  it('should unpublish from both hashes, in one transaction', async () => {
    await redisQueueLeaseStore.publishBacklog('a:1', 8400, 18);
    await redisQueueLeaseStore.unpublish('a:1');
    expect(mockClient.multi).toHaveBeenCalledTimes(2);
    expect(mockClient.hdel).not.toHaveBeenCalled();
    expect(hashes.get(BYTES)?.has('a:1')).toBe(false);
    expect(hashes.get(LEGACY)?.has('a:1')).toBe(false);
    expect(await redisQueueLeaseStore.liveBacklogs(TTL)).toEqual(new Map());
  });
});
