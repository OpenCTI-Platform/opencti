import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { testContext } from '../../../utils/testQuery';
import { DEFAULT_HEALTH_NOTIFICATION_DELAY_MS } from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import {
  MAX_HEALTH_NOTIFICATION_DELAY_MS,
  resolveIngestionHealthSettings,
  toGraphqlIngestionHealthSettings,
  validateIngestionHealthSettingsInput,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-settings';
import {
  HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED,
  HEALTH_CHECK_HEARTBEAT_MISSING,
  HEALTH_CHECK_LAST_RUN_FAILED,
  HEALTH_CHECK_SOURCE_ACCESS_DENIED,
  HEALTH_CHECK_USER_MISSING,
  HEALTH_CHECK_USER_MISSING_CAPABILITY,
  HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT,
  type HealthCheckCode,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { type IngestionHealthSettingsInput } from '../../../../src/generated/graphql';
import type { IngestionHealthSettings } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';
import { IngestionHealthCheckKind } from '../../../../src/generated/graphql';

// Every flag is enabled in the test configuration: only the flag off case overrides it
const { isFeatureEnabledMock } = vi.hoisted(() => ({ isFeatureEnabledMock: vi.fn() }));
vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  isFeatureEnabledMock.mockImplementation(actual.isFeatureEnabled);
  return { ...actual, isFeatureEnabled: isFeatureEnabledMock };
});

// The license is read from the cached settings: enterprise edition unless a case overrides it
const { getEntityFromCacheMock } = vi.hoisted(() => ({ getEntityFromCacheMock: vi.fn() }));
vi.mock('../../../../src/database/cache', () => ({ getEntityFromCache: getEntityFromCacheMock }));

describe('resolveIngestionHealthSettings', () => {
  it.each([
    ['never configured', undefined],
    ['null settings', null],
    ['settings without delay', {}],
  ])('should apply the defaults for %s: default delay, every check enabled', (_, settings) => {
    expect(resolveIngestionHealthSettings(settings)).toEqual({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS, disabled_health_checks: [] });
  });

  it('should keep the configured delay', () => {
    expect(resolveIngestionHealthSettings({ notification_delay: 60000 }).notification_delay).toEqual(60000);
  });

  it('should keep a configured delay of 0: not replaced by the default', () => {
    expect(resolveIngestionHealthSettings({ notification_delay: 0 }).notification_delay).toEqual(0);
  });

  it('should keep the disabled checks', () => {
    const settings = { disabled_health_checks: [HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_USER_MISSING] as HealthCheckCode[] };
    expect(resolveIngestionHealthSettings(settings).disabled_health_checks).toEqual([HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_USER_MISSING]);
  });

  it('should ignore a disabled check removed from the registry', () => {
    const settings = { disabled_health_checks: ['REMOVED_CHECK', HEALTH_CHECK_USER_MISSING] as HealthCheckCode[] };
    expect(resolveIngestionHealthSettings(settings).disabled_health_checks).toEqual([HEALTH_CHECK_USER_MISSING]);
  });
});

describe('toGraphqlIngestionHealthSettings', () => {
  const enabledCheck = (code: HealthCheckCode, label: string, kind: IngestionHealthCheckKind) => (
    { health_check_code: code, health_check_label: label, health_check_kind: kind, enabled: true }
  );

  it('should list every check of the registry with its kind, enabled when not configured', () => {
    expect(toGraphqlIngestionHealthSettings(undefined)).toEqual({
      notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
      disabled_health_checks: [],
      health_checks: [
        enabledCheck(HEALTH_CHECK_USER_MISSING, 'User is missing', IngestionHealthCheckKind.Configuration),
        enabledCheck(HEALTH_CHECK_USER_MISSING_CAPABILITY, 'User lacks required capability', IngestionHealthCheckKind.Configuration),
        enabledCheck(HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, 'User is not a service account', IngestionHealthCheckKind.Configuration),
        enabledCheck(HEALTH_CHECK_HEARTBEAT_MISSING, 'No heartbeat received', IngestionHealthCheckKind.Runtime),
        enabledCheck(HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, 'Feed or sync execution failed', IngestionHealthCheckKind.Runtime),
        enabledCheck(HEALTH_CHECK_SOURCE_ACCESS_DENIED, 'Source denied access', IngestionHealthCheckKind.Runtime),
        enabledCheck(HEALTH_CHECK_LAST_RUN_FAILED, 'Last run failed', IngestionHealthCheckKind.Runtime),
      ],
    });
  });

  it('should mark the disabled checks only', () => {
    const settings = { disabled_health_checks: [HEALTH_CHECK_HEARTBEAT_MISSING] as HealthCheckCode[] };
    const enabledByCode = Object.fromEntries(toGraphqlIngestionHealthSettings(settings).health_checks.map((check) => [check.health_check_code, check.enabled]));
    expect(enabledByCode).toEqual({
      [HEALTH_CHECK_USER_MISSING]: true,
      [HEALTH_CHECK_USER_MISSING_CAPABILITY]: true,
      [HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT]: true,
      [HEALTH_CHECK_HEARTBEAT_MISSING]: false,
      [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: true,
      [HEALTH_CHECK_SOURCE_ACCESS_DENIED]: true,
      [HEALTH_CHECK_LAST_RUN_FAILED]: true,
    });
  });
});

describe('validateIngestionHealthSettingsInput', () => {
  // Settings never configured: the current delay is the default one. Invalid values are cast: they can come from an untyped client
  const validate = (input: Record<string, unknown>, currentSettings?: IngestionHealthSettings) => {
    return validateIngestionHealthSettingsInput(testContext, input as IngestionHealthSettingsInput, currentSettings);
  };

  beforeEach(() => {
    getEntityFromCacheMock.mockResolvedValue({ valid_enterprise_edition: true });
  });

  afterEach(() => {
    isFeatureEnabledMock.mockClear();
    getEntityFromCacheMock.mockReset();
  });

  it('should accept an empty input: every field is kept unchanged', async () => {
    await expect(validate({})).resolves.toBeUndefined();
  });

  it.each([0, DEFAULT_HEALTH_NOTIFICATION_DELAY_MS, MAX_HEALTH_NOTIFICATION_DELAY_MS])('should accept a delay of %s ms', async (delay) => {
    await expect(validate({ notification_delay: delay })).resolves.toBeUndefined();
  });

  it.each([
    ['negative', -1],
    ['above one day', MAX_HEALTH_NOTIFICATION_DELAY_MS + 1],
    ['not an integer', 1.5],
    ['a string', '300000'],
    ['null', null],
  ])('should reject a delay %s', async (_, delay) => {
    await expect(validate({ notification_delay: delay })).rejects.toThrow('Invalid ingestion health notification delay');
  });

  it.each([
    ['empty', []],
    ['one check', [HEALTH_CHECK_HEARTBEAT_MISSING]],
    ['every check', [HEALTH_CHECK_USER_MISSING, HEALTH_CHECK_USER_MISSING_CAPABILITY, HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, HEALTH_CHECK_SOURCE_ACCESS_DENIED, HEALTH_CHECK_LAST_RUN_FAILED]],
  ])('should accept disabled checks %s, sent without the delay', async (_, disabled) => {
    await expect(validate({ disabled_health_checks: disabled })).resolves.toBeUndefined();
  });

  it.each([
    ['an unknown code', ['UNKNOWN_CHECK']],
    ['a duplicated code', [HEALTH_CHECK_USER_MISSING, HEALTH_CHECK_USER_MISSING]],
    ['a code that is not a string', [42]],
    ['not a list', HEALTH_CHECK_USER_MISSING],
    ['null', null],
  ])('should reject disabled checks with %s', async (_, disabled) => {
    await expect(validate({ disabled_health_checks: disabled })).rejects.toThrow('Invalid disabled health checks');
  });

  it('should reject a valid input when the feature is disabled', async () => {
    isFeatureEnabledMock.mockReturnValueOnce(false);
    await expect(validate({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS })).rejects.toThrow('Feature is disabled');
  });

  describe('in community edition', () => {
    const configured = { notification_delay: 60000 };

    beforeEach(() => {
      getEntityFromCacheMock.mockResolvedValue({ valid_enterprise_edition: false });
    });

    it('should reject a change of the delay', async () => {
      await expect(validate({ notification_delay: 60000 })).rejects.toThrow('Enterprise edition is not enabled');
      await expect(validate({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS }, configured)).rejects.toThrow('Enterprise edition is not enabled');
    });

    it('should accept the current delay: nothing changes', async () => {
      await expect(validate({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS })).resolves.toBeUndefined();
      await expect(validate({ notification_delay: 60000 }, configured)).resolves.toBeUndefined();
    });

    it('should accept the checks sent without the delay', async () => {
      await expect(validate({ disabled_health_checks: [HEALTH_CHECK_HEARTBEAT_MISSING] }, configured)).resolves.toBeUndefined();
    });

    it('should report an invalid delay as invalid, not as an EE restriction', async () => {
      await expect(validate({ notification_delay: -1 })).rejects.toThrow('Invalid ingestion health notification delay');
    });
  });
});
