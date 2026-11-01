import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from 'vitest';
import { ADMIN_USER, CONNECTOR_GROUP, getGroupIdByName, testContext } from '../../utils/testQuery';
import { ingestionHealthHandler } from '../../../src/manager/ingestionHealthManager';
import * as userActionListener from '../../../src/listener/UserActionListener';
import * as ingestionHealthSettings from '../../../src/modules/ingestionHealth/ingestionHealth-settings';
import { connectorDelete, pingConnector, registerConnector } from '../../../src/modules/connector/connector-domain';
import { redisSetConnectorHeartbeat } from '../../../src/modules/connector/connector-redis';
import { addUser, userDelete, userEditField } from '../../../src/modules/user/user-domain';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ConnectorType, IngestionHealthStatus } from '../../../src/generated/graphql';
import {
  HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED,
  HEALTH_CHECK_HEARTBEAT_MISSING,
  HEALTH_CHECK_REGISTRY,
  HEALTH_CHECK_USER_MISSING,
  HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT,
} from '../../../src/modules/ingestionHealth/ingestionHealth-registry';
import type { IngestionHealthFields } from '../../../src/modules/ingestionHealth/ingestionHealth-types';
import type { BasicStoreEntity } from '../../../src/types/store';
import type { BasicStoreEntityConnector } from '../../../src/modules/connector/connector-types';
import { addIngestion, ingestionDelete, patchRssIngestion } from '../../../src/modules/ingestion/ingestion-rss-domain';
import { ENTITY_TYPE_INGESTION_RSS } from '../../../src/modules/ingestion/ingestion-types';

// Scenario: an S3 connector is first registered with a user that does not exist anymore, then with a regular user,
// member of no organization. Its identity (an Organization) is under restricted access (authorized members): creating it
// is refused, the connector terminates and restarts in a loop.
// The refusal itself is not detected by the ingestion health (no check reads the connector errors): what is reported is
// that the user is not a service account (a service account would get edit access on the restricted identity), and,
// once the restarts slow down, the missing heartbeat.
// The access refusal is covered in middleware-organization-test and access-test: only the manager is tested here.
describe('Ingestion health manager: connector running as a regular user', () => {
  const CONNECTOR_ID = '5d1a5c3e-8b0f-4f43-9a52-6f3f0c1e2a01';
  const CONNECTOR_NAME = 'Ingestion health S3 connector';
  const DELETED_USER_ID = '5d1a5c3e-8b0f-4f43-9a52-6f3f0c1e2a02';
  const SIX_MINUTES_MS = 6 * 60 * 1000;
  let connectorUserId: string;
  let publishUserActionSpy: MockInstance;
  let resolveSettingsSpy: MockInstance;
  // Recorded here, not read from publishUserActionSpy.mock.calls: vitest clears the calls of the mocks before each test (clearMocks),
  // and the scenario expects the events of the previous tests
  const publishedActions: Parameters<typeof userActionListener.publishUserAction>[0][] = [];

  // Registered at each start of the connector, with the user of its token
  const registerAsUser = (userId: string) => registerConnector(
    testContext,
    ADMIN_USER,
    { id: CONNECTOR_ID, name: CONNECTOR_NAME, type: ConnectorType.ExternalImport },
    { connector_user_id: userId },
  );

  // A connector started by pycti pings continuously: it is one of the connectors whose heartbeat is checked
  const pingAsRunningConnector = () => pingConnector(testContext, ADMIN_USER, CONNECTOR_ID, null, {
    run_and_terminate: false,
    buffering: false,
    queue_threshold: 500,
    queue_messages_size: 0,
  });

  // The manager reads users and connectors from the cache, refreshed asynchronously by the platform events:
  // reloaded before each period so that the period sees the last writes
  const runManagerPeriod = async () => {
    resetCacheForEntity(ENTITY_TYPE_USER);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    await ingestionHealthHandler({ signal: new AbortController().signal });
  };

  const loadConnectorHealth = async () => {
    const connector = await storeLoadById<BasicStoreEntityConnector & IngestionHealthFields>(testContext, ADMIN_USER, CONNECTOR_ID, ENTITY_TYPE_CONNECTOR);
    return connector.ingestion_health;
  };

  // The manager evaluates every ingestion of the platform: only the events of the connector of the test are looked at
  const connectorHealthEvents = () => publishedActions
    .filter((action) => action.event_type === 'ingestion_health' && action.context_data?.id === CONNECTOR_ID);

  beforeAll(async () => {
    publishUserActionSpy = vi.spyOn(userActionListener, 'publishUserAction').mockImplementation(async (action) => {
      publishedActions.push(action);
      return [];
    });
    // Notified at the first period of a status: no need to wait for the default delay
    resolveSettingsSpy = vi.spyOn(ingestionHealthSettings, 'resolveIngestionHealthSettings').mockReturnValue({ notification_delay: 0, disabled_health_checks: [] });
    const connectorGroupId = await getGroupIdByName(CONNECTOR_GROUP.name);
    const connectorUser = await addUser(testContext, ADMIN_USER, {
      user_email: 'ingestion-health-s3-connector@opencti.io',
      name: 'Ingestion health S3 connector user',
      password: 's3-connector',
      groups: [connectorGroupId],
      objectOrganization: [],
      prevent_default_groups: true,
    });
    connectorUserId = connectorUser.id;
    await registerAsUser(DELETED_USER_ID);
    await pingAsRunningConnector();
  });

  afterAll(async () => {
    publishUserActionSpy.mockRestore();
    resolveSettingsSpy.mockRestore();
    await connectorDelete(testContext, ADMIN_USER, CONNECTOR_ID);
    await userDelete(testContext, ADMIN_USER, connectorUserId);
    resetCacheForEntity(ENTITY_TYPE_USER);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  it('should report the connector as degraded when its user is missing', async () => {
    await runManagerPeriod();
    const health = await loadConnectorHealth();
    expect(health?.status).toBe(IngestionHealthStatus.Degraded);
    // A missing user is not judged as a service account or not: only USER_MISSING is reported
    expect(health?.health_checks).toEqual([{ health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} }]);
    expect(health?.last_event_date).toBeDefined();
    const events = connectorHealthEvents();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      event_type: 'ingestion_health',
      event_scope: 'degraded',
      event_access: 'administration',
      status: 'error',
      message: `reports \`${CONNECTOR_NAME}\` (${ENTITY_TYPE_CONNECTOR}) as degraded: User is missing`,
      context_data: { id: CONNECTOR_ID, entity_type: ENTITY_TYPE_CONNECTOR, entity_name: CONNECTOR_NAME },
    });
  });

  it('should report the regular user once set, without notifying again the degraded status', async () => {
    const previousHealth = await loadConnectorHealth();
    // The connector restarts with the token of the regular user: registered and pinging again, its heartbeat is fresh
    await registerAsUser(connectorUserId);
    await pingAsRunningConnector();
    await runManagerPeriod();
    const health = await loadConnectorHealth();
    expect(health?.status).toBe(IngestionHealthStatus.Degraded);
    expect(health?.health_checks).toEqual([{ health_check_code: HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, health_check_metadata: {} }]);
    // Same status: its start and its notification are kept, only the checks change
    expect(health?.status_since).toEqual(previousHealth?.status_since);
    expect(health?.last_event_date).toEqual(previousHealth?.last_event_date);
    expect(connectorHealthEvents()).toHaveLength(1);
  });

  it('should report the connector as critical once the restarts slow down and the heartbeat is missing', async () => {
    await redisSetConnectorHeartbeat(CONNECTOR_ID, new Date(Date.now() - SIX_MINUTES_MS).toISOString());
    await runManagerPeriod();
    const health = await loadConnectorHealth();
    expect(health?.status).toBe(IngestionHealthStatus.Critical);
    expect(health?.health_checks).toEqual([
      { health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING, health_check_metadata: {} },
      { health_check_code: HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, health_check_metadata: {} },
    ]);
    const events = connectorHealthEvents();
    expect(events).toHaveLength(2);
    expect(events[1]).toMatchObject({
      event_scope: 'critical',
      status: 'error',
      message: `reports \`${CONNECTOR_NAME}\` (${ENTITY_TYPE_CONNECTOR}) as critical: No heartbeat received, User is not a service account`,
    });
  });

  it('should report the recovery once the user is turned into a service account and the connector pings again', async () => {
    await userEditField(testContext, ADMIN_USER, connectorUserId, [{ key: 'user_service_account', value: [true] }]);
    await pingAsRunningConnector();
    await runManagerPeriod();
    const health = await loadConnectorHealth();
    expect(health?.status).toBe(IngestionHealthStatus.Healthy);
    expect(health?.health_checks).toEqual([]);
    const events = connectorHealthEvents();
    expect(events).toHaveLength(3);
    expect(events[2]).toMatchObject({
      event_scope: 'recovered',
      status: 'success',
      message: `reports \`${CONNECTOR_NAME}\` (${ENTITY_TYPE_CONNECTOR}) as recovered`,
    });
  });
});

// Scenario: the heartbeat check is disabled on the platform, a connector pinging continuously runs with a deleted user,
// and the history of a failing feed cannot be read. The connector depends on no runtime data anymore: it must still be
// evaluated, only the feed needing the history is skipped until the next period.
describe('Ingestion health manager: runtime data read failure with the heartbeat check disabled', () => {
  const CONNECTOR_ID = '5d1a5c3e-8b0f-4f43-9a52-6f3f0c1e2a03';
  const CONNECTOR_NAME = 'Ingestion health connector without heartbeat check';
  const DELETED_USER_ID = '5d1a5c3e-8b0f-4f43-9a52-6f3f0c1e2a04';
  let feedId: string;
  let readFeedHistorySpy: MockInstance;
  let resolveSettingsSpy: MockInstance;

  beforeAll(async () => {
    resolveSettingsSpy = vi.spyOn(ingestionHealthSettings, 'resolveIngestionHealthSettings')
      .mockReturnValue({ notification_delay: 0, disabled_health_checks: [HEALTH_CHECK_HEARTBEAT_MISSING] });
    readFeedHistorySpy = vi.spyOn(HEALTH_CHECK_REGISTRY[HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED], 'getRuntimeData')
      .mockRejectedValue(new Error('Feed history unreachable'));
    await registerConnector(
      testContext,
      ADMIN_USER,
      { id: CONNECTOR_ID, name: CONNECTOR_NAME, type: ConnectorType.ExternalImport },
      { connector_user_id: DELETED_USER_ID },
    );
    await pingConnector(testContext, ADMIN_USER, CONNECTOR_ID, null, { run_and_terminate: false, buffering: false, queue_threshold: 500, queue_messages_size: 0 });
    const feed = await addIngestion(testContext, ADMIN_USER, {
      name: 'Ingestion health failing feed',
      uri: 'https://example.com/ingestion-health-rss-feed',
      user_id: ADMIN_USER.id,
    });
    feedId = feed.id;
    await patchRssIngestion(testContext, ADMIN_USER, feedId, { ingestion_running: true, last_execution_status: 'error' });
  });

  afterAll(async () => {
    readFeedHistorySpy.mockRestore();
    resolveSettingsSpy.mockRestore();
    await connectorDelete(testContext, ADMIN_USER, CONNECTOR_ID);
    await ingestionDelete(testContext, ADMIN_USER, feedId);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  it('should evaluate the connector and skip the failing feed only', async () => {
    resetCacheForEntity(ENTITY_TYPE_USER);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    await ingestionHealthHandler({ signal: new AbortController().signal });
    expect(readFeedHistorySpy).toHaveBeenCalled();
    const connector = await storeLoadById<BasicStoreEntityConnector & IngestionHealthFields>(testContext, ADMIN_USER, CONNECTOR_ID, ENTITY_TYPE_CONNECTOR);
    expect(connector.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
    expect(connector.ingestion_health?.health_checks).toEqual([{ health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} }]);
    const feed = await storeLoadById<BasicStoreEntity & IngestionHealthFields>(testContext, ADMIN_USER, feedId, ENTITY_TYPE_INGESTION_RSS);
    expect(feed.ingestion_health).toBeUndefined();
  });
});
