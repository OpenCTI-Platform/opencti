import { UnsupportedError } from '../../config/errors';
import { checkEnterpriseEdition } from '../../enterprise-edition/ee';
import type { IngestionHealthSettings as GraphqlIngestionHealthSettings, IngestionHealthSettingsInput } from '../../generated/graphql';
import type { AuthContext } from '../../types/user';
import { DEFAULT_HEALTH_NOTIFICATION_DELAY_MS } from './ingestionHealth-checks';
import { HEALTH_CHECK_REGISTRY, type HealthCheckCode, type HealthCheckDefinition, isHealthCheckAvailable, isHealthCheckCode } from './ingestionHealth-registry';
import type { IngestionHealthSettings } from './ingestionHealth-types';

export const MAX_HEALTH_NOTIFICATION_DELAY_MS = 24 * 60 * 60 * 1000;

// The settings as used, absent values replaced by their default: nothing is written on platforms never configured
export const resolveIngestionHealthSettings = (settings: IngestionHealthSettings | null | undefined): Required<IngestionHealthSettings> => ({
  notification_delay: settings?.notification_delay ?? DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
  // A code no longer in the registry is ignored: the check was removed
  disabled_health_checks: (settings?.disabled_health_checks ?? []).filter(isHealthCheckCode),
});

// Every check of the registry available on the platform, so that the settings list the checks added later as enabled
export const toGraphqlIngestionHealthSettings = (settings: IngestionHealthSettings | null | undefined): GraphqlIngestionHealthSettings => {
  const resolved = resolveIngestionHealthSettings(settings);
  return {
    ...resolved,
    health_checks: (Object.keys(HEALTH_CHECK_REGISTRY) as HealthCheckCode[]).filter(isHealthCheckAvailable).map((code) => {
      // Widened: the registry keeps the narrow type of each check, an optional field is absent from most of them
      const definition: HealthCheckDefinition = HEALTH_CHECK_REGISTRY[code];
      return {
        health_check_code: code,
        health_check_label: definition.label,
        health_check_description: definition.description_label,
        health_check_kind: definition.kind,
        enabled: !resolved.disabled_health_checks.includes(code),
      };
    }),
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
  currentSettings: IngestionHealthSettings | null | undefined,
) => {
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
