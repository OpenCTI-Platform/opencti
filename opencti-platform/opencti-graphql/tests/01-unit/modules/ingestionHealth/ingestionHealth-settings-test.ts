import { afterEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_HEALTH_NOTIFICATION_DELAY_MS } from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import {
  MAX_HEALTH_NOTIFICATION_DELAY_MS,
  resolveIngestionHealthSettings,
  validateIngestionHealthSettingsInput,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-settings';

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
  ])('should apply the default delay for %s', (_, settings) => {
    expect(resolveIngestionHealthSettings(settings)).toEqual({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS });
  });

  it('should keep the configured delay', () => {
    expect(resolveIngestionHealthSettings({ ingestion_health_settings: { notification_delay: 60000 } })).toEqual({ notification_delay: 60000 });
  });

  it('should keep a configured delay of 0: not replaced by the default', () => {
    expect(resolveIngestionHealthSettings({ ingestion_health_settings: { notification_delay: 0 } })).toEqual({ notification_delay: 0 });
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

  it('should reject a valid delay when the feature is disabled', () => {
    isFeatureEnabledMock.mockReturnValueOnce(false);
    expect(() => validateIngestionHealthSettingsInput(input({ notification_delay: DEFAULT_HEALTH_NOTIFICATION_DELAY_MS }))).toThrow('Feature is disabled');
  });
});
