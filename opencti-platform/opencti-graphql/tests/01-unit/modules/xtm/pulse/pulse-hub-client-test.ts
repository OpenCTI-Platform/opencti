import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import conf from '../../../../../src/config/conf';
import { PulseHubError, xtmHubPulseClient } from '../../../../../src/modules/xtm/hub/xtm-hub-pulse-client';
import { computeStableKey, computeTransportHash } from '../../../../../src/modules/xtm/pulse/pulse-hashing';
import { PulsePeriod, PulseRegionBucket, PulseSectorBucket } from '../../../../../src/generated/graphql';
import { PulseHubMock } from '../../../../utils/pulseHubMock';

const PLATFORM = { platformId: 'platform-under-test', platformToken: 'token-under-test' };
const KEY = computeStableKey('indicator', 'observable:ipv4-addr:value:198.51.100.7');

describe('XTM Hub Threat Pulse client', () => {
  const hub = new PulseHubMock();
  let previousOverride: string | undefined;

  beforeAll(async () => {
    previousOverride = conf.get('xtm:xtmhub_api_override_url');
    conf.set('xtm:xtmhub_api_override_url', await hub.start());
  });

  afterAll(async () => {
    conf.set('xtm:xtmhub_api_override_url', previousOverride);
    await hub.stop();
  });

  beforeEach(() => {
    hub.reset();
    hub.registerPlatform(PLATFORM.platformId, PLATFORM.platformToken);
  });

  const pushKey = async (batchId: string = randomUUID()) => {
    const day = hub.today();
    const { salt } = await xtmHubPulseClient.salt(PLATFORM, day);
    return xtmHubPulseClient.push(PLATFORM, {
      batch_id: batchId,
      day,
      sector_bucket: PulseSectorBucket.Finance,
      region_bucket: PulseRegionBucket.Europe,
      records: [{ hash: computeTransportHash(salt, KEY), object_type: 'indicator', event_kind: 'created', count: 1 }],
    });
  };

  it('should push hash and count records only', async () => {
    const result = await pushKey();
    expect(result.accepted).toBe(1);
    const push = hub.requests.find((request) => request.operation === 'pushPulse');
    expect(push?.rawBody).not.toContain('198.51.100.7');
    expect(push?.rawBody).not.toContain(KEY);
    expect(hub.ledger).toHaveLength(1);
    expect(hub.ledger[0]).toMatchObject({ key: KEY, objectType: 'indicator', sector: 'finance', region: 'europe' });
  });

  it('should count a retried batch once', async () => {
    const batchId = randomUUID();
    await pushKey(batchId);
    const retry = await pushKey(batchId);
    expect(retry.accepted).toBe(1);
    expect(hub.ledger).toHaveLength(1);
    expect(hub.ledger[0].count).toBe(1);
  });

  it('should require a contribution before reading', async () => {
    const day = hub.today();
    const promise = xtmHubPulseClient.lookup(PLATFORM, { day, object_type: 'indicator', hashes: [hub.hashOf(KEY, day)] });
    await expect(promise).rejects.toMatchObject({ code: 'contribution_required' });
  });

  it('should publish a value only once k distinct platforms contributed it', async () => {
    await pushKey();
    const day = hub.today();
    hub.seed(['p1', 'p2', 'p3'].map((platformId) => ({ platformId, key: KEY, objectType: 'indicator', eventKind: 'sighted', day, sector: 'finance', region: 'europe' })));
    const [belowThreshold] = await xtmHubPulseClient.lookup(PLATFORM, { day, object_type: 'indicator', hashes: [hub.hashOf(KEY, day)] });
    expect(belowThreshold.published).toBe(false);
    expect(belowThreshold.platforms_bucket).toBeNull();
    hub.seed([{ platformId: 'p4', key: KEY, objectType: 'indicator', eventKind: 'created', day, sector: 'healthcare', region: 'europe' }]);
    const [published] = await xtmHubPulseClient.lookup(PLATFORM, { day, object_type: 'indicator', hashes: [hub.hashOf(KEY, day)] });
    expect(published).toMatchObject({ published: true, platforms_bucket: '5-9', first_seen_network: day });
  });

  it('should return trending items under the requested salt', async () => {
    await pushKey();
    const day = hub.today();
    hub.seed(['p1', 'p2', 'p3', 'p4'].map((platformId) => ({ platformId, key: KEY, objectType: 'indicator', eventKind: 'sighted', day, sector: 'finance', region: 'europe' })));
    const trending = await xtmHubPulseClient.trending(PLATFORM, {
      day,
      period: PulsePeriod.Last_7Days,
      sector_bucket: PulseSectorBucket.Finance,
      region_bucket: null,
      object_types: null,
      first: 10,
    });
    expect(trending.items).toHaveLength(1);
    expect(trending.items[0].hash).toBe(hub.hashOf(KEY, day));
  });

  it('should map Hub errors to typed errors', async () => {
    hub.failNext('pushPulse', 'PULSE_RATE_LIMITED');
    await expect(pushKey()).rejects.toMatchObject({ code: 'rate_limited', retryAfterSeconds: 60 });
    const intruder = { platformId: PLATFORM.platformId, platformToken: 'wrong-token' };
    await expect(xtmHubPulseClient.status(intruder)).rejects.toMatchObject({ code: 'unauthenticated' });
    await expect(xtmHubPulseClient.salt(PLATFORM, '2001-01-01')).rejects.toMatchObject({ code: 'bad_request' });
  });

  it('should report an unreachable Hub', async () => {
    conf.set('xtm:xtmhub_api_override_url', 'http://127.0.0.1:1');
    try {
      await expect(xtmHubPulseClient.status(PLATFORM)).rejects.toBeInstanceOf(PulseHubError);
      await expect(xtmHubPulseClient.status(PLATFORM)).rejects.toMatchObject({ code: 'hub_unreachable' });
    } finally {
      conf.set('xtm:xtmhub_api_override_url', hub.url);
    }
  });

  it('should purge every contribution of the platform', async () => {
    await pushKey();
    const result = await xtmHubPulseClient.purge(PLATFORM);
    expect(result).toEqual({ success: true, deleted_records: 1 });
    expect(hub.ledger).toHaveLength(0);
  });
});
