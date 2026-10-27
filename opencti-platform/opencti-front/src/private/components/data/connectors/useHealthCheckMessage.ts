import { useFormatter } from '../../../../components/i18n';

// What the front needs to word one failing health check
export interface HealthCheckMessageSource {
  health_check_code: string;
  // In English, from the backend: may hold {key} placeholders filled from the metadata
  health_check_message?: string | null;
  // What describes the failure, see IngestionHealthCheck.health_check_metadata
  health_check_metadata?: unknown;
}

// Metadata whose value is an English text to translate, the other values are shown as is.
// capability_description: the description of a capability, translated as in the roles
const TRANSLATED_METADATA_KEYS = ['capability_description'];

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
        values[key] = TRANSLATED_METADATA_KEYS.includes(key) ? t_i18n(String(value)) : String(value);
      }
    }
    return t_i18n(message, { values });
  };

  return {
    getHealthCheckMessage,
  };
};

export default useHealthCheckMessage;
