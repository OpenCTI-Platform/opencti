import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Cluster from 'ioredis/built/cluster';
import Redis from 'ioredis';
import { createRedisClient, generateClusterNodes, generateNatMap } from '../../../src/database/redis';
import conf from '../../../src/config/conf';

describe('redis', () => {
  it('should cluster node configuration correctly generated', () => {
    const nodes = generateClusterNodes(['localhost:7000', 'localhost:7001']);
    expect(nodes.length).toBe(2);
    expect(nodes.at(0)?.host).toBe('localhost');
    expect(nodes.at(0)?.port).toBe(7000);
    expect(nodes.at(1)?.host).toBe('localhost');
    expect(nodes.at(1)?.port).toBe(7001);
  });

  it('should cluster nat map configuration correctly generated', () => {
    const nat = generateNatMap(['10.0.1.230:30001>203.0.113.73:30001', '10.0.1.231:30001>203.0.113.73:30002']);
    const entries = Object.entries(nat);
    expect(entries.length).toBe(2);
    const first = entries.at(0);
    expect(first?.at(0)).toBe('10.0.1.230:30001');
    const firstPortAndHost = first?.at(1) as { host: string; port: number; };
    expect(firstPortAndHost.host).toBe('203.0.113.73');
    expect(firstPortAndHost.port).toBe(30001);
    const second = entries.at(1);
    expect(second?.at(0)).toBe('10.0.1.231:30001');
    const secondPortAndHost = second?.at(1) as { host: string; port: number; };
    expect(secondPortAndHost.host).toBe('203.0.113.73');
    expect(secondPortAndHost.port).toBe(30002);
  });
});

describe('redis configuration checks', () => {
  let redisInitialConfiguration: any;
  beforeAll(() => {
    // Note that this works only for json conf, not env conf.
    redisInitialConfiguration = conf.get('redis');
  });
  afterAll(() => {
    conf.set('redis', redisInitialConfiguration);
  });

  it('should cluster configuration be correctly build without hostname key', async () => {
    conf.set('redis', {
      mode: 'cluster',
      namespace: '',
      hostnames: ['127.0.0.1:6379', '127.0.0.2:6379'],
      use_ssl: true,
      ca: ['/tmp/mycert.pem'],
      host_ip_family: 4,
      trimming: 2000000,
      username: 'unittestcluster',
      password: 'cluster',
    });
    const redisClient = await createRedisClient('unittest', false) as Cluster;
    expect(redisClient.isCluster).toBeTruthy();
    const redisOptions = redisClient.options;
    expect(redisOptions.redisOptions?.username).toBe('unittestcluster');
    expect(redisOptions.redisOptions?.password).toBe('cluster');
    expect(redisOptions.redisOptions?.tls?.servername).toBeUndefined();
  });

  it('should standalone configuration be correctly build', async () => {
    conf.set('redis', {
      mode: 'single',
      namespace: '',
      hostname: 'singlehostname', // this is actually override by REDIS__HOSTNAME env var in drone
      use_ssl: true,
      ca: ['/tmp/mycert.pem'],
      host_ip_family: 4,
      trimming: 2000000,
      username: 'unittest',
      password: 'single',
    });

    const redisClient = await createRedisClient('unittest', false) as Redis;
    expect(redisClient.isCluster).toBeFalsy();
    const redisOptions = redisClient.options;
    expect(redisOptions?.username).toBe('unittest');
    expect(redisOptions?.password).toBe('single');
  });

  it('should sentinel configuration be correctly build without hostname key', async () => {
    conf.set('redis', {
      mode: 'sentinel',
      namespace: '',
      hostnames: ['127.0.0.1:7001', '127.0.0.2:7002'],
      use_ssl: true,
      ca: ['/tmp/mycert.pem'],
      host_ip_family: 4,
      trimming: 2000000,
      username: 'unittestsentinel',
      password: 'sentinel',
      sentinel_master_name: 'sentinelmain'
    });
    const redisClient = await createRedisClient('unittest', false) as Redis;
    expect(redisClient.isCluster).toBeFalsy();
    const redisOptions = redisClient.options;
    expect(redisOptions.name).toBe('sentinelmain');
    const host1 = redisOptions.sentinels?.find((value) => value.host === '127.0.0.1');
    expect(host1?.host).toBe('127.0.0.1');
    expect(host1?.port).toBe(7001);
    const host2 = redisOptions.sentinels?.find((value) => value.host === '127.0.0.2');
    expect(host2?.host).toBe('127.0.0.2');
    expect(host2?.port).toBe(7002);
  });
});
