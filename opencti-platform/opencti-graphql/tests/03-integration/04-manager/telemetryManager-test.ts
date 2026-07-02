import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { defaultResource, resourceFromAttributes } from '@opentelemetry/resources';
import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { ATTR_SERVICE_INSTANCE_ID, ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { TELEMETRY_SERVICE_NAME, TelemetryMeterManager } from '../../../src/telemetry/TelemetryMeterManager';
import { PLATFORM_VERSION } from '../../../src/config/conf';
import { addDisseminationCount, fetchTelemetryData, TELEMETRY_GAUGE_DISSEMINATION, TELEMETRY_GAUGE_DRAFT_CREATION } from '../../../src/manager/telemetryManager';
import { redisClearTelemetry, redisGetTelemetry, redisSetTelemetryAdd } from '../../../src/database/redis';
import { waitInSec } from '../../../src/database/utils';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../utils/testQuery';
import { addSavedFilter, deleteSavedFilter, savedFilterEditAuthorizedMembers } from '../../../src/modules/savedFilter/savedFilter-domain';

describe('Telemetry manager test coverage', () => {
  let sharedFilterId: string;
  let unsharedFilterId: string;
  let shareWithCreatorFilterId: string;

  // create shared saved filters
  beforeAll(async () => {
    const savedFilter = JSON.stringify({ mode: 'and', filters: [{ key: 'objectLabel', value: [], operator: 'nil' }], filterGroups: [] });

    // Create a saved filter and share it with someone else than the creator
    const sharedSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
      name: 'telemetry-shared-filter',
      filters: savedFilter,
      scope: 'Incident',
    });
    sharedFilterId = sharedSavedFilter.id;
    await savedFilterEditAuthorizedMembers(testContext, ADMIN_USER, sharedFilterId, [
      { id: ADMIN_USER.id, access_right: 'admin' },
      { id: USER_EDITOR.id, access_right: 'view' },
    ]);

    // Create a saved filter that is NOT shared
    const unshareSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
      name: 'telemetry-unshared-filter',
      filters: savedFilter,
      scope: 'Incident',
    });
    unsharedFilterId = unshareSavedFilter.id;

    // Create a saved filter that is artificially shared with the creator at creation
    const shareWithCreatorSavedFilter = await addSavedFilter(testContext, ADMIN_USER, {
      name: 'telemetry-unshared-filter',
      filters: savedFilter,
      scope: 'Incident',
    });
    shareWithCreatorFilterId = shareWithCreatorSavedFilter.id;
    await savedFilterEditAuthorizedMembers(testContext, ADMIN_USER, shareWithCreatorFilterId, [
      { id: ADMIN_USER.id, access_right: 'admin' },
    ]);

    // Wait for cache refresh
    await waitInSec(2);
  });

  // delete the shared saved filters
  afterAll(async () => {
    await deleteSavedFilter(testContext, ADMIN_USER, sharedFilterId);
    await deleteSavedFilter(testContext, ADMIN_USER, unsharedFilterId);
    await deleteSavedFilter(testContext, ADMIN_USER, shareWithCreatorFilterId);
  });

  test('Verify that metrics get collected from both elastic and redis', async () => {
    // GIVEN a configured telemetry
    const filigranResource = resourceFromAttributes({
      [ATTR_SERVICE_NAME]: TELEMETRY_SERVICE_NAME,
      [ATTR_SERVICE_VERSION]: PLATFORM_VERSION,
      [ATTR_SERVICE_INSTANCE_ID]: 'api-test-telemetry-id',
      'service.instance.creation': new Date().toUTCString(),
    });
    const resource = defaultResource().merge(filigranResource);

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

    // 1 shared saved filter should be counted: sharedSavedFilter, because it is shared with others than just the creator
    expect(filigranTelemetryMeterManager.sharedSavedFiltersCount).toEqual(1);
  });
});
