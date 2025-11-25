import { describe, expect, test } from 'vitest';
import { Resource } from '@opentelemetry/resources';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { SEMRESATTRS_SERVICE_INSTANCE_ID } from '@opentelemetry/semantic-conventions/build/src/resource/SemanticResourceAttributes';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../../../src/telemetry/TelemetryMeterManager';
import { PLATFORM_VERSION } from '../../../src/config/conf';
import { addDisseminationCount, fetchTelemetryData, TELEMETRY_GAUGE_DISSEMINATION, TELEMETRY_GAUGE_DRAFT_CREATION } from '../../../src/manager/telemetryManager';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../../../src/database/redis';
import { waitInSec } from '../../../src/database/utils';

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
    const disseminationGaugeValueReset = await redisGetTelemetry(TELEMETRY_GAUGE_DISSEMINATION);
    expect(disseminationGaugeValueReset).toBe(0);
    const draftGaugeValue = await redisGetTelemetry(TELEMETRY_GAUGE_DRAFT_CREATION);
    expect(draftGaugeValue).toBe(0);

    // AND GIVEN some "user event" from this node
    const DISSEMINATION_EVENT_NODE1 = 5;
    const DISSEMINATION_EVENT_NODE2 = 3;
    for (let i = 0; i < DISSEMINATION_EVENT_NODE1; i += 1) {
      await addDisseminationCount();
    }
    // AND GIVEN some "user event" from another node (simulated by a direct redis update)
    await redisSetTelemetryAdd(TELEMETRY_GAUGE_DISSEMINATION, DISSEMINATION_EVENT_NODE2);

    const loopCount = 3; // 3' max
    let loopCurrent = 0;

    const isRedisUpdatedCallback = async () => {
      const disseminationGaugeValue = await redisGetTelemetry(TELEMETRY_GAUGE_DISSEMINATION);
      return disseminationGaugeValue === (DISSEMINATION_EVENT_NODE1 + DISSEMINATION_EVENT_NODE2);
    };
    let isRedisUpdated = await isRedisUpdatedCallback();
    while (!isRedisUpdated && loopCurrent < loopCount) {
      await waitInSec(1);
      isRedisUpdated = await isRedisUpdatedCallback();
      loopCurrent += 1;
    }

    // WHEN data is fetched from elastic (platform wide gauges) and redis (user event gauge)
    await fetchTelemetryData(filigranTelemetryMeterManager);

    // THEN all data stored in the in-memory class are accurate
    // TODO later: most of them are not working since it depends on previous tests.
    // Need to analyse better how testSetup and globalSetup are working.
    // expect(filigranTelemetryMeterManager.usersCount).toBe(getCounterTotal(ENTITY_TYPE_USER));
    expect(filigranTelemetryMeterManager.disseminationCount).toBe(DISSEMINATION_EVENT_NODE1 + DISSEMINATION_EVENT_NODE2);
    expect(filigranTelemetryMeterManager.instancesCount).toBe(1);
    expect(filigranTelemetryMeterManager.isEEActivated).toBe(1); // 1 mean true
    // filigranTelemetryMeterManager.activeConnectorsCount : count cannot be verified since there are many ways to create internal connectors.
    // expect(filigranTelemetryMeterManager.draftCount).toBe(getCounterTotal(ENTITY_TYPE_DRAFT_WORKSPACE));
    // expect(filigranTelemetryMeterManager.workbenchCount).toBe(getCounterTotal(ENTITY_TYPE_WORKSPACE));
  });
});
