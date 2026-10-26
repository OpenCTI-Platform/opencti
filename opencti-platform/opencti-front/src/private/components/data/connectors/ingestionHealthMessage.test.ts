import { describe, expect, it } from 'vitest';
import { getHealthCheckMessage } from './ingestionHealthMessage';

// Echoes the key with its values, to see what is translated
const t_i18n = (message: string, options?: { values?: Record<string, string | number> }) => (
  options?.values ? `${message}|${JSON.stringify(options.values)}` : message
);

const MISSING_CAPABILITY_MESSAGE = 'User lacks required capability: "{capability}"';

describe('getHealthCheckMessage', () => {
  it('should translate a message with placeholders, with the translated description of the capability', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: { capability: 'CONNECTORAPI' } };
    expect(getHealthCheckMessage(check, t_i18n))
      .toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability":"Connectors API usage: register, ping, export push ..."}`);
  });

  it('should show the name of a capability without description', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: { capability: 'OTHER' } };
    expect(getHealthCheckMessage(check, t_i18n)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability":"OTHER"}`);
  });

  it('should fill any placeholder with its metadata value as is when the key has no translation', () => {
    const check = { health_check_code: 'ANY', health_check_message: 'Failed with {status} on {url}', health_check_metadata: { status: 404, url: 'https://feed' } };
    expect(getHealthCheckMessage(check, t_i18n)).toBe('Failed with {status} on {url}|{"status":"404","url":"https://feed"}');
  });

  it('should translate a message without placeholder', () => {
    const translateUserMissing = (message: string) => (message === 'User is missing' ? 'Utilisateur manquant' : message);
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING', health_check_message: 'User is missing' }, translateUserMissing)).toBe('Utilisateur manquant');
  });

  it('should translate the message keeping the placeholder when it has no metadata', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: {} };
    expect(getHealthCheckMessage(check, t_i18n)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability":"{capability}"}`);
  });

  it('should fall back to the code without message', () => {
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING' }, t_i18n)).toBe('USER_MISSING');
  });
});
