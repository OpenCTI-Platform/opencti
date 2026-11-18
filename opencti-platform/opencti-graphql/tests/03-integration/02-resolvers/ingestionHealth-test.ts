import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as ee from '../../../src/enterprise-edition/ee';
import { UnsupportedError } from '../../../src/config/errors';
import { ingestionHealthHandler } from '../../../src/manager/ingestionHealthManager';
import { connectorDelete, pingConnector, registerConnector } from '../../../src/modules/connector/connector-domain';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ConnectorType } from '../../../src/generated/graphql';
import { HEALTH_CHECK_REGISTRY, HEALTH_CHECK_USER_MISSING } from '../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { ADMIN_USER, testContext, USER_EDITOR, USER_PLATFORM_ADMIN } from '../../utils/testQuery';
import { queryAsAdminWithError, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden, queryAsUserWithSuccess } from '../../utils/testQueryHelper';

const DEFAULT_NOTIFICATION_DELAY = 5 * 60 * 1000;
// Every check of the registry: the expectations follow the checks added later
const ALL_CHECK_CODES = Object.keys(HEALTH_CHECK_REGISTRY);
const ALL_CHECKS_ENABLED = Object.fromEntries(ALL_CHECK_CODES.map((code) => [code, true]));

const READ_QUERY = gql`
  query ingestionHealthSettings {
    ingestionHealthSettings {
      notification_delay
      disabled_health_checks
      health_checks {
        health_check_code
        enabled
      }
    }
  }
`;

const EDIT_QUERY = gql`
  mutation IngestionHealthSettingsEdit($input: IngestionHealthSettingsInput!) {
    ingestionHealthSettingsEdit(input: $input) {
      notification_delay
      disabled_health_checks
      health_checks {
        health_check_code
        enabled
      }
    }
  }
`;

const SETTINGS_ID_QUERY = gql`
  query settingsId {
    settings {
      id
    }
  }
`;

const SETTINGS_EDIT_QUERY = gql`
  mutation SettingsEdit($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const CONNECTOR_HEALTH_QUERY = gql`
  query connectorIngestionHealth($id: String!) {
    connector(id: $id) {
      id
      ingestionHealth {
        status
        status_since
        healthChecks {
          health_check_code
          health_check_message
          health_check_metadata
          health_check_kind
          health_check_severity
        }
      }
    }
  }
`;

interface IngestionHealthSettingsResult {
  notification_delay: number;
  disabled_health_checks: string[];
  health_checks: { health_check_code: string; enabled: boolean }[];
}

const readSettings = async (): Promise<IngestionHealthSettingsResult> => {
  resetCacheForEntity(ENTITY_TYPE_SETTINGS);
  const { data } = await queryAsAdminWithSuccess({ query: READ_QUERY, variables: {} });
  return data?.ingestionHealthSettings;
};
const editSettings = (input: Record<string, unknown>) => ({ query: EDIT_QUERY, variables: { input } });
const editDelay = (notification_delay: number) => editSettings({ notification_delay });
const editChecks = (disabled_health_checks: string[]) => editSettings({ disabled_health_checks });
const enabledByCode = (settings: IngestionHealthSettingsResult) => Object.fromEntries(settings.health_checks.map((check) => [check.health_check_code, check.enabled]));

describe('Ingestion health settings resolver', () => {
  // Changing the delay is an EE feature: the community edition case overrides it
  const checkEnterpriseEditionSpy = vi.spyOn(ee, 'checkEnterpriseEdition');

  beforeAll(() => {
    checkEnterpriseEditionSpy.mockResolvedValue();
  });

  afterAll(async () => {
    // Back to the defaults of a platform never configured, for the next test files
    await queryAsAdminWithSuccess(editSettings({ notification_delay: DEFAULT_NOTIFICATION_DELAY, disabled_health_checks: [] }));
    vi.restoreAllMocks();
  });

  it('should apply the defaults when not configured: default delay, every check enabled', async () => {
    const settings = await readSettings();
    expect(settings.notification_delay).toEqual(DEFAULT_NOTIFICATION_DELAY);
    expect(settings.disabled_health_checks).toEqual([]);
    expect(enabledByCode(settings)).toEqual(ALL_CHECKS_ENABLED);
  });

  it('should reject reading the settings without SETTINGS_SETPARAMETERS capability', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, { query: READ_QUERY, variables: {} });
  });

  it('should update the notification delay', async () => {
    const { data } = await queryAsAdminWithSuccess(editDelay(60000));
    expect(data?.ingestionHealthSettingsEdit.notification_delay).toEqual(60000);
    const settings = await readSettings();
    expect(settings.notification_delay).toEqual(60000);
  });

  it('should reject an out of bounds notification delay and keep the stored one', async () => {
    const error = 'Invalid ingestion health notification delay, expected an integer between 0 and 86400000 ms';
    await queryAsAdminWithError(editDelay(24 * 60 * 60 * 1000 + 1), error);
    await queryAsAdminWithError(editDelay(-1), error);
    const settings = await readSettings();
    expect(settings.notification_delay).toEqual(60000);
  });

  it('should allow updating the notification delay with SETTINGS_SETPARAMETERS capability', async () => {
    const { data } = await queryAsUserWithSuccess(USER_PLATFORM_ADMIN, editDelay(120000));
    expect(data?.ingestionHealthSettingsEdit.notification_delay).toEqual(120000);
  });

  it('should reject updating the notification delay without SETTINGS_SETPARAMETERS capability', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, editDelay(0));
    const settings = await readSettings();
    expect(settings.notification_delay).toEqual(120000);
  });

  it('should disable a health check and keep the delay not sent', async () => {
    const { data } = await queryAsAdminWithSuccess(editChecks(['HEARTBEAT_MISSING']));
    expect(data?.ingestionHealthSettingsEdit.disabled_health_checks).toEqual(['HEARTBEAT_MISSING']);
    expect(enabledByCode(data?.ingestionHealthSettingsEdit)).toEqual({ ...ALL_CHECKS_ENABLED, HEARTBEAT_MISSING: false });
    const settings = await readSettings();
    expect(settings.disabled_health_checks).toEqual(['HEARTBEAT_MISSING']);
    expect(settings.notification_delay).toEqual(120000);
  });

  it('should allow disabling health checks with SETTINGS_SETPARAMETERS capability', async () => {
    const disabled = ['HEARTBEAT_MISSING', 'USER_NOT_SERVICE_ACCOUNT'];
    const { data } = await queryAsUserWithSuccess(USER_PLATFORM_ADMIN, editChecks(disabled));
    expect(data?.ingestionHealthSettingsEdit.disabled_health_checks).toEqual(disabled);
  });

  it('should reject unknown or duplicated disabled health checks and keep the stored ones', async () => {
    const error = `Invalid disabled health checks, expected distinct codes among ${ALL_CHECK_CODES.join(', ')}`;
    await queryAsAdminWithError(editChecks(['UNKNOWN_CHECK']), error);
    await queryAsAdminWithError(editChecks(['USER_MISSING', 'USER_MISSING']), error);
    const settings = await readSettings();
    expect(settings.disabled_health_checks).toEqual(['HEARTBEAT_MISSING', 'USER_NOT_SERVICE_ACCOUNT']);
  });

  it('should reject disabling health checks without SETTINGS_SETPARAMETERS capability', async () => {
    await queryAsUserIsExpectedForbidden(USER_EDITOR, editChecks([]));
    const settings = await readSettings();
    expect(settings.disabled_health_checks).toEqual(['HEARTBEAT_MISSING', 'USER_NOT_SERVICE_ACCOUNT']);
  });

  it('should keep the checks when the delay is sent alone', async () => {
    const { data } = await queryAsAdminWithSuccess(editDelay(DEFAULT_NOTIFICATION_DELAY));
    expect(data?.ingestionHealthSettingsEdit.notification_delay).toEqual(DEFAULT_NOTIFICATION_DELAY);
    expect(data?.ingestionHealthSettingsEdit.disabled_health_checks).toEqual(['HEARTBEAT_MISSING', 'USER_NOT_SERVICE_ACCOUNT']);
  });

  it('should keep the checks editable in community edition, but not the delay', async () => {
    checkEnterpriseEditionSpy.mockRejectedValue(UnsupportedError('Enterprise edition is not enabled'));
    await queryAsAdminWithError(editDelay(60000), 'Enterprise edition is not enabled');
    const { data } = await queryAsAdminWithSuccess(editChecks(['HEARTBEAT_MISSING']));
    expect(data?.ingestionHealthSettingsEdit.disabled_health_checks).toEqual(['HEARTBEAT_MISSING']);
    expect(data?.ingestionHealthSettingsEdit.notification_delay).toEqual(DEFAULT_NOTIFICATION_DELAY);
    checkEnterpriseEditionSpy.mockResolvedValue();
  });

  it('should reject the edition through the platform settings, even with BYPASS: the settings would not be validated', async () => {
    const { data } = await queryAsAdminWithSuccess({ query: SETTINGS_ID_QUERY, variables: {} });
    await queryAsAdminWithError(
      { query: SETTINGS_EDIT_QUERY, variables: { id: data?.settings.id, input: { key: 'ingestion_health_settings', value: [{ notification_delay: -1 }] } } },
      'You cannot update incompatible attribute',
    );
  });

  it('should keep both fields when they are edited at the same time', async () => {
    await Promise.all([
      queryAsAdminWithSuccess(editDelay(60000)),
      queryAsUserWithSuccess(USER_PLATFORM_ADMIN, editChecks(['USER_MISSING'])),
    ]);
    const settings = await readSettings();
    expect(settings.notification_delay).toEqual(60000);
    expect(settings.disabled_health_checks).toEqual(['USER_MISSING']);
  });
});

describe('Ingestion health field resolver', () => {
  const CONNECTOR_ID = '5d1a5c3e-8b0f-4f43-9a52-6f3f0c1e2a11';
  const DELETED_USER_ID = '5d1a5c3e-8b0f-4f43-9a52-6f3f0c1e2a12';

  const readConnectorHealth = async () => {
    const { data } = await queryAsAdminWithSuccess({ query: CONNECTOR_HEALTH_QUERY, variables: { id: CONNECTOR_ID } });
    return data?.connector.ingestionHealth;
  };

  // The manager reads users and connectors from the cache, refreshed asynchronously by the platform events
  const runManagerPeriod = async () => {
    resetCacheForEntity(ENTITY_TYPE_USER);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
    await ingestionHealthHandler({ signal: new AbortController().signal });
  };

  beforeAll(async () => {
    // Registered with the user of a token that does not exist anymore: reported as USER_MISSING
    await registerConnector(
      testContext,
      ADMIN_USER,
      { id: CONNECTOR_ID, name: 'Ingestion health resolver connector', type: ConnectorType.ExternalImport },
      { connector_user_id: DELETED_USER_ID },
    );
    await pingConnector(testContext, ADMIN_USER, CONNECTOR_ID, null, { run_and_terminate: false, buffering: false, queue_threshold: 500, queue_messages_size: 0 });
  });

  afterAll(async () => {
    await connectorDelete(testContext, ADMIN_USER, CONNECTOR_ID);
    resetCacheForEntity(ENTITY_TYPE_USER);
    resetCacheForEntity(ENTITY_TYPE_CONNECTOR);
  });

  it('should resolve the ingestion health to null until the manager evaluates the connector', async () => {
    expect(await readConnectorHealth()).toBeNull();
  });

  it('should resolve the stored health of the connector once evaluated', async () => {
    await runManagerPeriod();
    const health = await readConnectorHealth();
    expect(health.status).toEqual('degraded');
    expect(health.status_since).toBeDefined();
    // Kind, severity and message are derived from the stored code
    expect(health.healthChecks).toEqual([{
      health_check_code: HEALTH_CHECK_USER_MISSING,
      health_check_message: 'User is missing',
      health_check_metadata: {},
      health_check_kind: 'configuration',
      health_check_severity: 'advisory',
    }]);
  });
});
