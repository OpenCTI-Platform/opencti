import { describe, expect, it } from 'vitest';
import { buildClientAuthentication } from '../../../../src/modules/authenticationProvider/provider-oidc';

describe('buildClientAuthentication', () => {
  it('should send the secret as Basic auth when token_endpoint_auth_method is client_secret_basic', () => {
    const clientAuth = buildClientAuthentication({ token_endpoint_auth_method: 'client_secret_basic' }, 'secret1');
    expect(clientAuth).toBeDefined();
    const body = new URLSearchParams();
    const headers = new Headers();
    clientAuth!({ issuer: 'https://idp.example.com' }, { client_id: 'client1' }, body, headers);
    const expected = `Basic ${Buffer.from('client1:secret1').toString('base64')}`;
    expect(headers.get('authorization')).toBe(expected);
    expect(body.has('client_secret')).toBe(false);
  });

  it('should keep the openid-client default when token_endpoint_auth_method is not set', () => {
    expect(buildClientAuthentication({}, 'secret1')).toBeUndefined();
  });

  it('should keep the openid-client default for client_secret_post', () => {
    expect(buildClientAuthentication({ token_endpoint_auth_method: 'client_secret_post' }, 'secret1')).toBeUndefined();
  });
});
