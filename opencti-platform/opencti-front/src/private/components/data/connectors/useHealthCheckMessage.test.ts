import { renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import useHealthCheckMessage from './useHealthCheckMessage';

// Echoes the key with its values, to see what is translated. One message has a real translation
vi.mock('../../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (message: string, options?: { values?: Record<string, string | number> }) => {
      if (message === 'User is missing') return 'Utilisateur manquant';
      return options?.values ? `${message}|${JSON.stringify(options.values)}` : message;
    },
  }),
}));

const MISSING_CAPABILITY_MESSAGE = 'User lacks required capability: "{capability}"';

describe('useHealthCheckMessage', () => {
  const { result } = renderHook(() => useHealthCheckMessage());
  const { getHealthCheckMessage } = result.current;

  it('should translate a message with placeholders, with the translated description of the capability', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: { capability: 'CONNECTORAPI' } };
    expect(getHealthCheckMessage(check))
      .toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability":"Connectors API usage: register, ping, export push ..."}`);
  });

  it('should show the name of a capability without description', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: { capability: 'OTHER' } };
    expect(getHealthCheckMessage(check)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability":"OTHER"}`);
  });

  it('should fill any placeholder with its metadata value as is when the key has no translation', () => {
    const check = { health_check_code: 'ANY', health_check_message: 'Failed with {status} on {url}', health_check_metadata: { status: 404, url: 'https://feed' } };
    expect(getHealthCheckMessage(check)).toBe('Failed with {status} on {url}|{"status":"404","url":"https://feed"}');
  });

  it('should translate a message without placeholder', () => {
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING', health_check_message: 'User is missing' })).toBe('Utilisateur manquant');
  });

  it('should translate the message keeping the placeholder when it has no metadata', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: {} };
    expect(getHealthCheckMessage(check)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability":"{capability}"}`);
  });

  it('should fall back to the code without message', () => {
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING' })).toBe('USER_MISSING');
  });
});
