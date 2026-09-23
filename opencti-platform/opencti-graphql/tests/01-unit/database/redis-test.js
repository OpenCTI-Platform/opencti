import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Cluster, Redis } from 'ioredis';

const redisConfig = vi.hoisted(() => ({
  mode: 'cluster',
  hostname: 'redis.example.test',
  hostnames: ['node-1.example.test:6379', 'node-2.example.test:6379'],
  tlsServername: undefined,
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal();
  const redisOverrides = () => ({
    'redis:mode': redisConfig.mode,
    'redis:hostname': redisConfig.hostname,
    'redis:hostnames': redisConfig.hostnames,
    'redis:tls_servername': redisConfig.tlsServername,
    'redis:ca': [],
    'redis:database': 0,
    'redis:port': 6379,
    'redis:nat_map': [],
  });
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key) => {
        const overrides = redisOverrides();
        return key in overrides ? overrides[key] : actual.default.get(key);
      },
    },
    booleanConf: (key, fallback) => (key === 'redis:use_ssl' ? true : actual.booleanConf(key, fallback)),
    configureCA: vi.fn(() => ({ ca: ['test-ca'] })),
  };
});

vi.mock('../../../src/config/credentials', () => ({
  enrichWithRemoteCredentials: vi.fn(async (_service, auth) => auth),
}));

vi.mock('../../../src/schema/schema-relationsRef', () => ({
  schemaRelationsRefDefinition: {
    getAllInputNames: vi.fn(() => ['createdBy', 'objectMarking', 'objectLabel']),
  },
}));

import { createRedisClient, generateClusterNodes, generateNatMap, removeResolvedRefs } from '../../../src/database/redis';

describe('Redis client creation', () => {
  let client;

  beforeEach(() => {
    redisConfig.mode = 'cluster';
    redisConfig.hostname = 'redis.example.test';
    redisConfig.hostnames = ['node-1.example.test:6379', 'node-2.example.test:6379'];
    redisConfig.tlsServername = undefined;
    vi.clearAllMocks();
  });

  afterEach(() => {
    client?.disconnect();
  });

  it('should not pin the TLS servername in cluster mode', async () => {
    client = await createRedisClient('test');

    expect(client).toBeInstanceOf(Cluster);
    expect(client.options.redisOptions.tls).toMatchObject({ ca: ['test-ca'] });
    expect(client.options.redisOptions.tls).not.toHaveProperty('servername');
  });

  it('should use the configured hostname as TLS servername in single mode', async () => {
    redisConfig.mode = 'single';

    client = await createRedisClient('test');

    expect(client).toBeInstanceOf(Redis);
    expect(client.options.tls).toMatchObject({ ca: ['test-ca'], servername: 'redis.example.test' });
  });

  it('should use an explicit TLS servername for every cluster node', async () => {
    redisConfig.tlsServername = 'redis-cluster.example.test';

    client = await createRedisClient('test');

    expect(client).toBeInstanceOf(Cluster);
    expect(client.options.redisOptions.tls).toMatchObject({
      ca: ['test-ca'],
      servername: 'redis-cluster.example.test',
    });
  });

  it('should override the hostname with an explicit TLS servername in single mode', async () => {
    redisConfig.mode = 'single';
    redisConfig.tlsServername = 'redis-service.example.test';

    client = await createRedisClient('test');

    expect(client).toBeInstanceOf(Redis);
    expect(client.options.tls).toMatchObject({
      ca: ['test-ca'],
      servername: 'redis-service.example.test',
    });
  });
});

describe('Redis cluster configuration', () => {
  it('should cluster node configuration correctly generated', () => {
    expect(generateClusterNodes(['localhost:7000', 'localhost:7001'])).toEqual([
      { host: 'localhost', port: 7000 },
      { host: 'localhost', port: 7001 },
    ]);
  });

  it('should cluster nat map configuration correctly generated', () => {
    expect(generateNatMap(['10.0.1.230:30001>203.0.113.73:30001', '10.0.1.231:30001>203.0.113.73:30002'])).toEqual({
      '10.0.1.230:30001': { host: '203.0.113.73', port: 30001 },
      '10.0.1.231:30001': { host: '203.0.113.73', port: 30002 },
    });
  });
});

describe('removeResolvedRefs', () => {
  it('should strip resolved ref fields and INPUT_OBJECTS', () => {
    const instance = {
      id: 'malware-1',
      name: 'MalwareA',
      'created-by': 'identity-1',
      createdBy: { id: 'identity-1' },
      'object-marking': ['marking-1'],
      objectMarking: [{ definition: 'TLP:RED' }],
      objectLabel: [{ value: 'malware' }],
      objects: [{ id: 'obj-1' }],
    };

    expect(removeResolvedRefs(instance)).toEqual({
      id: 'malware-1',
      name: 'MalwareA',
      'created-by': 'identity-1',
      'object-marking': ['marking-1'],
    });
  });

  it('should keep all fields when there are no resolved refs', () => {
    const instance = { id: 'a', name: 'B', description: 'C' };
    expect(removeResolvedRefs(instance)).toEqual(instance);
  });
});
