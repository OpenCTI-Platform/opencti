import { describe, expect, it } from 'vitest';
import { computeUsageMetrics } from '../../../src/manager/platformUsageMetricsManager';
import { redisSetPlatformUsageMetrics } from '../../../src/database/redis';
import { adoptSharedUsageMetrics, ENGINE_STATUSES, getPlatformUsageMetrics } from '../../../src/telemetry/platformHealthMetrics';
import { buildXtmOneHealthSnapshot } from '../../../src/modules/xtm/one/xtm-one-health';
import { ADMIN_USER, testContext } from '../../utils/testQuery';

// The values depend on the test platform: only that every metric is read from the real dependencies is checked.
describe('Platform usage metrics manager', () => {
  it('should collect every usage metric from the platform dependencies', async () => {
    const metrics = await computeUsageMetrics();

    expect(metrics.es_used_size).toEqual(expect.any(Number));
    expect(ENGINE_STATUSES).toContain(metrics.es_status);
    expect(metrics.es_disk_used_percent).toEqual(expect.any(Number));
    expect(metrics.s3_used_size).toEqual(expect.any(Number));
    expect(metrics.queue_consumers).toEqual(expect.any(Object));
  });

  it('should expose the collected search engine health to /health and to the XTM One snapshot', async () => {
    await redisSetPlatformUsageMetrics(await computeUsageMetrics(), 60);
    await adoptSharedUsageMetrics();
    const { es_status, es_disk_used_percent } = getPlatformUsageMetrics();

    const snapshot = await buildXtmOneHealthSnapshot(testContext, ADMIN_USER);

    expect(snapshot.search_engine).toEqual({ status: es_status, disk_used_percent: es_disk_used_percent });
    expect(ENGINE_STATUSES).toContain(snapshot.search_engine?.status);
    expect(snapshot.connectors).toEqual(expect.any(Array));
    expect(snapshot.rabbitmq).toEqual({ queue_messages: expect.any(Number), consumers: expect.any(Number) });
  });
});
