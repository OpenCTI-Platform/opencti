import { useFormatter } from '../../../../components/i18n';

// What the front needs to word one failing health check
export interface HealthCheckMessageSource {
  health_check_code: string;
  // In English, from the backend: may hold {key} placeholders filled from the metadata
  health_check_message?: string | null;
  // What describes the failure, see IngestionHealthCheck.health_check_metadata
  health_check_metadata?: unknown;
}

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

// Description of the capabilities a check may ask for, translated as in the roles
const CAPABILITY_DESCRIPTIONS: Record<string, string> = {
  CONNECTORAPI: 'Connectors API usage: register, ping, export push ...',
};

// How a metadata value is shown in a message, by metadata key. A key absent here shows its value as is
const METADATA_VALUE_TRANSLATIONS: Record<string, (value: string, t_i18n: Translate) => string> = {
  capability: (capability, t_i18n) => (CAPABILITY_DESCRIPTIONS[capability] ? t_i18n(CAPABILITY_DESCRIPTIONS[capability]) : capability),
};

const PLACEHOLDER_PATTERN = /\{(\w+)\}/g;

// Translated message of a failing check, its {key} placeholders filled with the values of its metadata.
// A message without translation (computed by the backend) shows as is
const useHealthCheckMessage = () => {
  const { t_i18n } = useFormatter();

  const getHealthCheckMessage = (check: HealthCheckMessageSource): string => {
    const message = check.health_check_message;
    if (!message) {
      return check.health_check_code;
    }
    const keys = [...message.matchAll(PLACEHOLDER_PATTERN)].map(([, key]) => key);
    const metadata = (check.health_check_metadata ?? {}) as Record<string, unknown>;
    const values: Record<string, string> = {};
    for (const key of keys) {
      const value = metadata[key];
      if (typeof value !== 'string' && typeof value !== 'number') {
        // Nothing to fill the placeholder with: it stays as is, a missing value would make the translation throw
        values[key] = `{${key}}`;
      } else {
        const translateValue = METADATA_VALUE_TRANSLATIONS[key];
        values[key] = translateValue ? translateValue(String(value), t_i18n) : String(value);
      }
    }
    return t_i18n(message, { values });
  };

  return {
    getHealthCheckMessage,
  };
};

export default useHealthCheckMessage;
