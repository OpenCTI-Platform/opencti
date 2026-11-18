import { describe, expect, it, vi } from 'vitest';
import { buildClientAuthentication } from '../../../../src/modules/authenticationProvider/provider-oidc';
import type { AuthenticationProviderLogger } from '../../../../src/modules/authenticationProvider/providers-logger';

const createLogger = (): AuthenticationProviderLogger => ({
  success: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  deferError: vi.fn(),
});

describe('buildClientAuthentication', () => {
  it('should send the secret as Basic auth when token_endpoint_auth_method is client_secret_basic', () => {
    const clientAuth = buildClientAuthentication(createLogger(), { token_endpoint_auth_method: 'client_secret_basic' }, 'secret1');
    expect(clientAuth).toBeDefined();
    const body = new URLSearchParams();
    const headers = new Headers();
    clientAuth!({ issuer: 'https://idp.example.com' }, { client_id: 'client1' }, body, headers);
    const expected = `Basic ${Buffer.from('client1:secret1').toString('base64')}`;
    expect(headers.get('authorization')).toBe(expected);
    expect(body.has('client_secret')).toBe(false);
  });

  it('should keep the openid-client default when token_endpoint_auth_method is not set', () => {
    expect(buildClientAuthentication(createLogger(), {}, 'secret1')).toBeUndefined();
  });

  it('should keep the openid-client default for client_secret_post', () => {
    expect(buildClientAuthentication(createLogger(), { token_endpoint_auth_method: 'client_secret_post' }, 'secret1')).toBeUndefined();
  });

  it('should warn and keep the openid-client default for an unsupported value', () => {
    const logger = createLogger();
    expect(buildClientAuthentication(logger, { token_endpoint_auth_method: 'private_key_jwt' }, 'secret1')).toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(
      'Unsupported token_endpoint_auth_method, falling back to client_secret_post',
      { token_endpoint_auth_method: 'private_key_jwt' },
    );
  });
});
