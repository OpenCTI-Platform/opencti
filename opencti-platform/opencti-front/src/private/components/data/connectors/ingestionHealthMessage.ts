// What the front needs to word one failing health check
export interface HealthCheckMessageSource {
  health_check_code: string;
  // In English, from the backend: the fallback
  health_check_message?: string | null;
  // What describes the failure, see IngestionHealthCheck.health_check_metadata
  health_check_metadata?: unknown;
}

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

// Description of the capabilities a check may ask for, translated as in the roles
const CAPABILITY_DESCRIPTIONS: Record<string, string> = {
  CONNECTORAPI: 'Connectors API usage: register, ping, export push ...',
};

// Translated message of a failing check. A check needing translated parameters adds its case here, any other keeps the backend message
export const getHealthCheckMessage = (check: HealthCheckMessageSource, t_i18n: Translate): string => {
  const metadata = (check.health_check_metadata ?? {}) as Record<string, unknown>;
  if (check.health_check_code === 'USER_MISSING_CAPABILITY' && typeof metadata.capability === 'string') {
    const description = CAPABILITY_DESCRIPTIONS[metadata.capability];
    return t_i18n('User lacks required capability: "{capability}"', { values: { capability: description ? t_i18n(description) : metadata.capability } });
  }
  return check.health_check_message ?? check.health_check_code;
};
