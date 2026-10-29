import { INGESTION_HEALTH_FEATURE_FLAG } from '../../config/conf';
import { UnsupportedError } from '../../config/errors';
import { enforceEnableFeatureFlag } from '../../utils/access';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { IngestionHealthSettings as GraphqlIngestionHealthSettings, IngestionHealthSettingsInput } from '../../generated/graphql';
import type { AuthContext } from '../../types/user';
import { DEFAULT_HEALTH_NOTIFICATION_DELAY_MS } from './ingestionHealth-checks';
import { HEALTH_CHECK_REGISTRY, type HealthCheckCode, isHealthCheckCode } from './ingestionHealth-registry';
import type { IngestionHealthSettings } from './ingestionHealth-types';

export const MAX_HEALTH_NOTIFICATION_DELAY_MS = 24 * 60 * 60 * 1000;

// The settings as used, absent values replaced by their default: nothing is written on platforms never configured
export const resolveIngestionHealthSettings = (settings: { ingestion_health_settings?: IngestionHealthSettings | null }): Required<IngestionHealthSettings> => ({
  notification_delay: settings.ingestion_health_settings?.notification_delay ?? DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
  // A code no longer in the registry is ignored: the check was removed
  disabled_health_checks: (settings.ingestion_health_settings?.disabled_health_checks ?? []).filter(isHealthCheckCode),
});

// Every check of the registry, so that the settings list the checks added later as enabled
export const toGraphqlIngestionHealthSettings = (settings: { ingestion_health_settings?: IngestionHealthSettings | null }): GraphqlIngestionHealthSettings => {
  const resolved = resolveIngestionHealthSettings(settings);
  return {
    ...resolved,
    health_checks: (Object.keys(HEALTH_CHECK_REGISTRY) as HealthCheckCode[]).map((code) => ({
      health_check_code: code,
      health_check_label: HEALTH_CHECK_REGISTRY[code].label,
      health_check_kind: HEALTH_CHECK_REGISTRY[code].kind,
      health_check_severity: HEALTH_CHECK_REGISTRY[code].severity,
      enabled: !resolved.disabled_health_checks.includes(code),
    })),
  };
};

const isValidNotificationDelay = (delay: unknown) => Number.isInteger(delay)
  && (delay as number) >= 0
  && (delay as number) <= MAX_HEALTH_NOTIFICATION_DELAY_MS;

// Known codes, each once
const isValidDisabledHealthChecks = (codes: unknown) => Array.isArray(codes)
  && codes.every(isHealthCheckCode)
  && new Set(codes).size === codes.length;

// A field left out of the input is kept unchanged: only the fields sent are validated
export const validateIngestionHealthSettingsInput = async (
  context: AuthContext,
  input: IngestionHealthSettingsInput,
  currentSettings: { ingestion_health_settings?: IngestionHealthSettings | null },
) => {
  enforceEnableFeatureFlag(INGESTION_HEALTH_FEATURE_FLAG);
  const { notification_delay, disabled_health_checks } = input;
  if (notification_delay !== undefined) {
    if (!isValidNotificationDelay(notification_delay)) {
      throw UnsupportedError(`Invalid ingestion health notification delay, expected an integer between 0 and ${MAX_HEALTH_NOTIFICATION_DELAY_MS} ms`);
    }
    // Changing the delay is an EE feature since activity events are EE
    if (notification_delay !== resolveIngestionHealthSettings(currentSettings).notification_delay) {
      await checkEnterpriseEdition(context);
    }
  }
  if (disabled_health_checks !== undefined && !isValidDisabledHealthChecks(disabled_health_checks)) {
    throw UnsupportedError(`Invalid disabled health checks, expected distinct codes among ${Object.keys(HEALTH_CHECK_REGISTRY).join(', ')}`);
  }
};
