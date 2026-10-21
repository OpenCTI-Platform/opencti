import { INGESTION_HEALTH_FEATURE_FLAG } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { DEFAULT_HEALTH_NOTIFICATION_DELAY_MS } from './ingestionHealth-checks';
import type { IngestionHealthSettings } from './ingestionHealth-types';

export const MAX_HEALTH_NOTIFICATION_DELAY_MS = 24 * 60 * 60 * 1000;

// The settings as used, absent values replaced by their default: nothing is written on platforms never configured
export const resolveIngestionHealthSettings = (settings: { ingestion_health_settings?: IngestionHealthSettings | null }): Required<IngestionHealthSettings> => ({
  notification_delay: settings.ingestion_health_settings?.notification_delay ?? DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
});

const isValidNotificationDelay = (delay: unknown) => Number.isInteger(delay)
  && (delay as number) >= 0
  && (delay as number) <= MAX_HEALTH_NOTIFICATION_DELAY_MS;

// Edited as a whole object from the Parameters page: the object is replaced, so every field must be valid
export const validateIngestionHealthSettingsInput = (input: { object_path?: string | null; value: unknown[] }) => {
  enforceEnableFeatureFlag(INGESTION_HEALTH_FEATURE_FLAG);
  const [value] = input.value ?? [];
  if (input.object_path || !value || typeof value !== 'object' || Array.isArray(value)) {
    throw UnsupportedError('Ingestion health settings must be edited as a whole object');
  }
  const { notification_delay } = value as IngestionHealthSettings;
  if (!isValidNotificationDelay(notification_delay)) {
    throw UnsupportedError(`Invalid ingestion health notification delay, expected an integer between 0 and ${MAX_HEALTH_NOTIFICATION_DELAY_MS} ms`);
  }
};
