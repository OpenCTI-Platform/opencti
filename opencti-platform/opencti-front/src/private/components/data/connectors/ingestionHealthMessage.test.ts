import { describe, expect, it } from 'vitest';
import { getHealthCheckMessage } from './ingestionHealthMessage';

// Echoes the key with its values, to see what is translated
const t_i18n = (message: string, options?: { values?: Record<string, string | number> }) => (
  options?.values ? `${message}|${JSON.stringify(options.values)}` : message
);

describe('getHealthCheckMessage', () => {
  it('should translate the description of the missing capability', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: 'fallback', health_check_metadata: { capability: 'CONNECTORAPI' } };
    expect(getHealthCheckMessage(check, t_i18n))
      .toBe('User lacks required capability: "{capability}"|{"capability":"Connectors API usage: register, ping, export push ..."}');
  });

  it('should show the name of a capability without description', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_metadata: { capability: 'OTHER' } };
    expect(getHealthCheckMessage(check, t_i18n)).toBe('User lacks required capability: "{capability}"|{"capability":"OTHER"}');
  });

  it('should fall back to the message of the backend, then to the code', () => {
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING', health_check_message: 'User is missing' }, t_i18n)).toBe('User is missing');
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING_CAPABILITY', health_check_metadata: {} }, t_i18n)).toBe('USER_MISSING_CAPABILITY');
  });
});
