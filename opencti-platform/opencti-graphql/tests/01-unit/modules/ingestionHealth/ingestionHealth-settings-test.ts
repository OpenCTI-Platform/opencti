import { afterEach, describe, expect, it, vi } from 'vitest';
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
  HEALTH_CHECK_USER_MISSING,
  HEALTH_CHECK_USER_MISSING_CAPABILITY,
  HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT,
  type HealthCheckCode,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity } from '../../../../src/generated/graphql';

// Every flag is enabled in the test configuration: only the flag off case overrides it
const { isFeatureEnabledMock } = vi.hoisted(() => ({ isFeatureEnabledMock: vi.fn() }));
vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  isFeatureEnabledMock.mockImplementation(actual.isFeatureEnabled);
  return { ...actual, isFeatureEnabled: isFeatureEnabledMock };
});

const input = (value: unknown, object_path?: string) => ({ key: 'ingestion_health_settings', value: [value], ...(object_path ? { object_path } : {}) });

describe('resolveIngestionHealthSettings', () => {
  it.each([
    ['never configured', {}],
    ['null settings', { ingestion_health_settings: null }],
    ['settings without delay', { ingestion_health_settings: {} }],
  ])('should apply the defaults for %s: default delay, every check enabled', (_, settings) => {
    expect(resolveIngestionHealthSettings(settings)).toEqual({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS, disabled_health_checks: [] });
  });

  it('should keep the configured delay', () => {
    expect(resolveIngestionHealthSettings({ ingestion_health_settings: { notification_delay: 60000 } }).notification_delay).toEqual(60000);
  });

  it('should keep a configured delay of 0: not replaced by the default', () => {
    expect(resolveIngestionHealthSettings({ ingestion_health_settings: { notification_delay: 0 } }).notification_delay).toEqual(0);
  });

  it('should keep the disabled checks', () => {
    const settings = { ingestion_health_settings: { disabled_health_checks: [HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_USER_MISSING] as HealthCheckCode[] } };
    expect(resolveIngestionHealthSettings(settings).disabled_health_checks).toEqual([HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_USER_MISSING]);
  });

  it('should ignore a disabled check removed from the registry', () => {
    const settings = { ingestion_health_settings: { disabled_health_checks: ['REMOVED_CHECK', HEALTH_CHECK_USER_MISSING] as HealthCheckCode[] } };
    expect(resolveIngestionHealthSettings(settings).disabled_health_checks).toEqual([HEALTH_CHECK_USER_MISSING]);
  });
});

describe('toGraphqlIngestionHealthSettings', () => {
  const enabledCheck = (code: HealthCheckCode, label: string, kind: IngestionHealthCheckKind, severity: IngestionHealthCheckSeverity) => (
    { health_check_code: code, health_check_label: label, health_check_kind: kind, health_check_severity: severity, enabled: true }
  );

  it('should list every check of the registry with its kind and severity, enabled when not configured', () => {
    expect(toGraphqlIngestionHealthSettings({})).toEqual({
      notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
      disabled_health_checks: [],
      health_checks: [
        enabledCheck(HEALTH_CHECK_USER_MISSING, 'User is missing', IngestionHealthCheckKind.Configuration, IngestionHealthCheckSeverity.Blocking),
        enabledCheck(HEALTH_CHECK_USER_MISSING_CAPABILITY, 'User lacks required capability', IngestionHealthCheckKind.Configuration, IngestionHealthCheckSeverity.Blocking),
        enabledCheck(HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, 'User is not a service account', IngestionHealthCheckKind.Configuration, IngestionHealthCheckSeverity.Advisory),
        enabledCheck(HEALTH_CHECK_HEARTBEAT_MISSING, 'No heartbeat received', IngestionHealthCheckKind.Runtime, IngestionHealthCheckSeverity.Blocking),
        enabledCheck(HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, 'Feed or sync execution failed', IngestionHealthCheckKind.Runtime, IngestionHealthCheckSeverity.Blocking),
      ],
    });
  });

  it('should mark the disabled checks only', () => {
    const settings = { ingestion_health_settings: { disabled_health_checks: [HEALTH_CHECK_HEARTBEAT_MISSING] as HealthCheckCode[] } };
    const enabledByCode = Object.fromEntries(toGraphqlIngestionHealthSettings(settings).health_checks.map((check) => [check.health_check_code, check.enabled]));
    expect(enabledByCode).toEqual({
      [HEALTH_CHECK_USER_MISSING]: true,
      [HEALTH_CHECK_USER_MISSING_CAPABILITY]: true,
      [HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT]: true,
      [HEALTH_CHECK_HEARTBEAT_MISSING]: false,
      [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: true,
    });
  });
});

describe('validateIngestionHealthSettingsInput', () => {
  afterEach(() => {
    isFeatureEnabledMock.mockClear();
  });

  it.each([0, DEFAULT_HEALTH_NOTIFICATION_DELAY_MS, MAX_HEALTH_NOTIFICATION_DELAY_MS])('should accept a delay of %s ms', (delay) => {
    expect(() => validateIngestionHealthSettingsInput(input({ notification_delay: delay }))).not.toThrow();
  });

  it.each([
    ['negative', -1],
    ['above one day', MAX_HEALTH_NOTIFICATION_DELAY_MS + 1],
    ['not an integer', 1.5],
    ['a string', '300000'],
    ['null', null],
  ])('should reject a delay %s', (_, delay) => {
    expect(() => validateIngestionHealthSettingsInput(input({ notification_delay: delay }))).toThrow('Invalid ingestion health notification delay');
  });

  it('should reject settings without delay', () => {
    expect(() => validateIngestionHealthSettingsInput(input({}))).toThrow('Invalid ingestion health notification delay');
  });

  it.each([
    ['a number', 300000],
    ['an array', [{ notification_delay: 300000 }]],
    ['null', null],
  ])('should reject a value that is %s instead of an object', (_, value) => {
    expect(() => validateIngestionHealthSettingsInput(input(value))).toThrow('Ingestion health settings must be edited as a whole object');
  });

  it('should reject an empty value', () => {
    expect(() => validateIngestionHealthSettingsInput({ value: [] })).toThrow('Ingestion health settings must be edited as a whole object');
  });

  it('should reject the edition of a single field: the object would not be validated as a whole', () => {
    expect(() => validateIngestionHealthSettingsInput(input(300000, '/ingestion_health_settings/notification_delay')))
      .toThrow('Ingestion health settings must be edited as a whole object');
  });

  it.each([
    ['absent', undefined],
    ['empty', []],
    ['one check', [HEALTH_CHECK_HEARTBEAT_MISSING]],
    ['every check', [HEALTH_CHECK_USER_MISSING, HEALTH_CHECK_USER_MISSING_CAPABILITY, HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]],
  ])('should accept disabled checks %s', (_, disabled) => {
    expect(() => validateIngestionHealthSettingsInput(input({ notification_delay: 0, disabled_health_checks: disabled }))).not.toThrow();
  });

  it.each([
    ['an unknown code', ['UNKNOWN_CHECK']],
    ['a duplicated code', [HEALTH_CHECK_USER_MISSING, HEALTH_CHECK_USER_MISSING]],
    ['a code that is not a string', [42]],
    ['not a list', HEALTH_CHECK_USER_MISSING],
    ['null', null],
  ])('should reject disabled checks with %s', (_, disabled) => {
    expect(() => validateIngestionHealthSettingsInput(input({ notification_delay: 0, disabled_health_checks: disabled }))).toThrow('Invalid disabled health checks');
  });

  it('should reject a valid delay when the feature is disabled', () => {
    isFeatureEnabledMock.mockReturnValueOnce(false);
    expect(() => validateIngestionHealthSettingsInput(input({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS }))).toThrow('Feature is disabled');
  });
});
