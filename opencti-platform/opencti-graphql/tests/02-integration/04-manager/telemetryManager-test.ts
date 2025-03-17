import { describe, expect, test } from 'vitest';
import { Resource } from '@opentelemetry/resources';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { SEMRESATTRS_SERVICE_INSTANCE_ID } from '@opentelemetry/semantic-conventions/build/src/resource/SemanticResourceAttributes';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../../../src/telemetry/TelemetryMeterManager';
import { PLATFORM_VERSION } from '../../../src/config/conf';
import { fetchTelemetryData } from '../../../src/manager/telemetryManager';
import { TESTING_USERS } from '../../utils/testQuery';
import { redisClearTelemetry, redisSetTelemetryAdd } from '../../../src/database/redis';
import { addDisseminationCount } from '../../../src/modules/disseminationList/disseminationList-domain';

describe('Telemetry manager test coverage', () => {
  test('Verify that metrics get collected from both elastic and redis', async () => {
    // GIVEN a configured telemetry
    const filigranResource = new Resource({
      [SEMRESATTRS_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
      [SEMRESATTRS_SERVICE_VERSION]: PLATFORM_VERSION,
      [SEMRESATTRS_SERVICE_INSTANCE_ID]: 'api-test-telemetry-id',
      'service.instance.creation': new Date().toUTCString()
    });
    const resource = Resource.default().merge(filigranResource);

    // no readers so no data is sent for this test
    const filigranMeterProvider = new MeterProvider(({ resource, readers: [] }));
    const filigranTelemetryMeterManager = new TelemetryMeterManager(filigranMeterProvider);
    filigranTelemetryMeterManager.registerFiligranTelemetry();
    // AND Given starting from clean state in redis
    await redisClearTelemetry();

    // AND GIVEN some "user event" from this node
    const DISSEMINATION_EVENT_NODE1 = 5;
    const DISSEMINATION_EVENT_NODE2 = 3;
    for (let i = 0; i < DISSEMINATION_EVENT_NODE1; i += 1) {
      await addDisseminationCount();
    }
    // AND GIVEN some "user event" from another node (simulated by a redis update)
    await redisSetTelemetryAdd('disseminationCount', DISSEMINATION_EVENT_NODE2);

    // WHEN data is fetched from elastic (platform wide gauges) and redis (user event gauge)
    await fetchTelemetryData(filigranTelemetryMeterManager);

    // THEN all data stored in the in-memory class are accurate
    expect(filigranTelemetryMeterManager.usersCount).toBe(TESTING_USERS.length + 1);
    expect(filigranTelemetryMeterManager.disseminationCount).toBe(DISSEMINATION_EVENT_NODE1 + DISSEMINATION_EVENT_NODE2);
  });
});
