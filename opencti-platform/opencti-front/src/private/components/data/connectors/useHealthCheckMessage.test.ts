import { renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import useHealthCheckMessage from './useHealthCheckMessage';

// Used by the mock below, hoisted above the other declarations
const { CONNECTORAPI_DESCRIPTION } = vi.hoisted(() => ({ CONNECTORAPI_DESCRIPTION: 'Connectors API usage: register, ping, export push ...' }));

// Echoes the key with its values, to see what is translated. One message has a real translation
vi.mock('../../../../components/i18n', () => ({
  useFormatter: () => ({
    t_i18n: (message: string, options?: { values?: Record<string, string | number> }) => {
      if (message === 'User is missing') return 'Utilisateur manquant';
      if (message === CONNECTORAPI_DESCRIPTION) return "Utilisation de l'API des connecteurs";
      return options?.values ? `${message}|${JSON.stringify(options.values)}` : message;
    },
  }),
}));

const MISSING_CAPABILITY_MESSAGE = 'User lacks required capability: "{capability_description}"';

describe('useHealthCheckMessage', () => {
  const { result } = renderHook(() => useHealthCheckMessage());
  const { getHealthCheckMessage } = result.current;

  it('should translate a message with placeholders, with the description of the capability translated as in the roles', () => {
    const metadata = { capability: 'CONNECTORAPI', capability_description: CONNECTORAPI_DESCRIPTION };
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: metadata };
    expect(getHealthCheckMessage(check)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability_description":"Utilisation de l'API des connecteurs"}`);
  });

  it('should show a capability description without translation as is', () => {
    const metadata = { capability: 'OTHER', capability_description: 'OTHER' };
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: metadata };
    expect(getHealthCheckMessage(check)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability_description":"OTHER"}`);
  });

  it('should fill any placeholder with its metadata value as is when the key has no translation', () => {
    const check = { health_check_code: 'ANY', health_check_message: 'Failed with {status} on {url}', health_check_metadata: { status: 404, url: 'https://feed' } };
    expect(getHealthCheckMessage(check)).toBe('Failed with {status} on {url}|{"status":"404","url":"https://feed"}');
  });

  it('should translate the template of a failed execution, the failure filled as is', () => {
    const metadata = { http_status: 404, http_status_text: 'Not Found', failure_description: 'HTTP 404 Not Found' };
    const check = { health_check_code: 'FEED_AND_SYNC_EXECUTION_FAILED', health_check_message: 'Feed execution failed: {failure_description}', health_check_metadata: metadata };
    expect(getHealthCheckMessage(check)).toBe('Feed execution failed: {failure_description}|{"failure_description":"HTTP 404 Not Found"}');
  });

  it('should translate a message without placeholder', () => {
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING', health_check_message: 'User is missing' })).toBe('Utilisateur manquant');
  });

  it('should translate the message keeping the placeholder when it has no metadata', () => {
    const check = { health_check_code: 'USER_MISSING_CAPABILITY', health_check_message: MISSING_CAPABILITY_MESSAGE, health_check_metadata: {} };
    expect(getHealthCheckMessage(check)).toBe(`${MISSING_CAPABILITY_MESSAGE}|{"capability_description":"{capability_description}"}`);
  });

  it('should fall back to the code without message', () => {
    expect(getHealthCheckMessage({ health_check_code: 'USER_MISSING' })).toBe('USER_MISSING');
  });
});
