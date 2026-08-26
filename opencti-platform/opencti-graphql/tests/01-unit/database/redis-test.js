import { beforeEach, describe, expect, it, vi } from 'vitest';

const redisConfig = vi.hoisted(() => ({
  mode: 'cluster',
  hostname: 'redis.example.test',
  hostnames: ['node-1.example.test:6379', 'node-2.example.test:6379'],
}));

const redisClientMocks = vi.hoisted(() => {
  const Redis = vi.fn(function Redis(options) {
    this.options = options;
    this.on = vi.fn().mockReturnValue(this);
  });
  const Cluster = vi.fn(function Cluster(nodes, options) {
    this.nodes = nodes;
    this.options = options;
    this.on = vi.fn().mockReturnValue(this);
  });
  Redis.Cluster = Cluster;
  return { Redis, Cluster };
});

vi.mock('ioredis', () => redisClientMocks);

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal();
  const redisOverrides = () => ({
    'redis:mode': redisConfig.mode,
    'redis:hostname': redisConfig.hostname,
    'redis:hostnames': redisConfig.hostnames,
    'redis:ca': [],
    'redis:database': 0,
    'redis:port': 6379,
    'redis:nat_map': [],
  });
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key) => (key in redisOverrides() ? redisOverrides()[key] : actual.default.get(key)),
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

import { createRedisClient, removeResolvedRefs } from '../../../src/database/redis';
import { generateClusterNodes, generateNatMap } from '../../../src/database/redis';

describe('redis', () => {
  beforeEach(() => {
    redisConfig.mode = 'cluster';
    vi.clearAllMocks();
  });

  it('should not pin the TLS servername in cluster mode', async () => {
    await createRedisClient('test');

    expect(redisClientMocks.Cluster).toHaveBeenCalledOnce();
    const [nodes, options] = redisClientMocks.Cluster.mock.calls[0];
    expect(nodes).toEqual([
      { host: 'node-1.example.test', port: 6379 },
      { host: 'node-2.example.test', port: 6379 },
    ]);
    expect(options.redisOptions.tls).toEqual({ ca: ['test-ca'] });
  });

  it('should use the configured hostname as TLS servername in single mode', async () => {
    redisConfig.mode = 'single';

    await createRedisClient('test');

    expect(redisClientMocks.Redis).toHaveBeenCalledOnce();
    const [options] = redisClientMocks.Redis.mock.calls[0];
    expect(options.tls).toEqual({ ca: ['test-ca'], servername: 'redis.example.test' });
  });

  it('should cluster node configuration correctly generated', () => {
    const nodes = generateClusterNodes(['localhost:7000', 'localhost:7001']);
    expect(nodes.length).toBe(2);
    expect(nodes.at(0).host).toBe('localhost');
    expect(nodes.at(0).port).toBe(7000);
    expect(nodes.at(1).host).toBe('localhost');
    expect(nodes.at(1).port).toBe(7001);
  });

  it('should cluster nat map configuration correctly generated', () => {
    const nat = generateNatMap(['10.0.1.230:30001>203.0.113.73:30001', '10.0.1.231:30001>203.0.113.73:30002']);
    const entries = Object.entries(nat);
    expect(entries.length).toBe(2);
    const first = entries.at(0);
    expect(first.at(0)).toBe('10.0.1.230:30001');
    expect(first.at(1).host).toBe('203.0.113.73');
    expect(first.at(1).port).toBe(30001);
    const second = entries.at(1);
    expect(second.at(0)).toBe('10.0.1.231:30001');
    expect(second.at(1).host).toBe('203.0.113.73');
    expect(second.at(1).port).toBe(30002);
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
