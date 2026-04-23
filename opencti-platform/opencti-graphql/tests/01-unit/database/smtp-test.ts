import { describe, expect, it } from 'vitest';
import { buildSmtpAuth as buildSmtpAuthImpl } from '../../../src/database/smtp';

type SmtpCredentials = {
  username?: string;
  password?: string;
  oauthUser?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthAccessToken?: string;
};

// The JS source infers all destructured params as required; cast to the intended optional API.
const buildSmtpAuth = buildSmtpAuthImpl as (
  authType: string | undefined,
  credentials: SmtpCredentials,
) => ReturnType<typeof buildSmtpAuthImpl>;

// ==========================================================================
// buildSmtpAuth — OAuth2
// ==========================================================================

describe('buildSmtpAuth — OAuth2', () => {
  const oauth2Config = {
    oauthUser: 'user@example.com',
    oauthClientId: 'my-client-id',
    oauthClientSecret: 'my-client-secret',
    oauthAccessToken: 'my-access-token',
  };

  it('should return an OAuth2 auth object when authType is "oauth2"', () => {
    const result = buildSmtpAuth('oauth2', oauth2Config);
    expect(result).toStrictEqual({
      type: 'OAuth2',
      user: 'user@example.com',
      clientId: 'my-client-id',
      clientSecret: 'my-client-secret',
      accessToken: 'my-access-token',
    });
  });

  it('should use oauthUser and not username even when both are provided', () => {
    const result = buildSmtpAuth('oauth2', {
      ...oauth2Config,
      username: 'legacy@example.com',
      password: 'legacy-pass',
    });
    expect(result).toHaveProperty('type', 'OAuth2');
    expect(result).toHaveProperty('user', 'user@example.com');
    expect(result).not.toHaveProperty('pass');
  });

  it('should throw an error when oauth_* required fields are missing', () => {
    expect(() => buildSmtpAuth('oauth2', {})).toThrow(
      'SMTP OAuth2 configuration is incomplete: oauth_user, oauth_client_id, oauth_client_secret and oauth_access_token are all required.',
    );
  });

  it('should throw an error when only some oauth_* fields are provided', () => {
    expect(() => buildSmtpAuth('oauth2', { oauthUser: 'user@example.com' })).toThrow(
      'SMTP OAuth2 configuration is incomplete',
    );
  });
});

// ==========================================================================
// buildSmtpAuth — Basic Auth
// ==========================================================================

describe('buildSmtpAuth — Basic Auth', () => {
  it('should return a Basic Auth object when authType is "basic" and username is set', () => {
    const result = buildSmtpAuth('basic', { username: 'user@example.com', password: 'mypassword' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: 'mypassword' });
  });

  it('should return a Basic Auth object when authType is not set (defaults to basic)', () => {
    const result = buildSmtpAuth(undefined, { username: 'user@example.com', password: 'mypassword' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: 'mypassword' });
  });

  it('should set pass to empty string when password is absent', () => {
    const result = buildSmtpAuth('basic', { username: 'user@example.com' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: '' });
  });

  it('should return undefined when username is absent', () => {
    const result = buildSmtpAuth('basic', {});
    expect(result).toBeUndefined();
  });

  it('should return undefined when username is an empty string', () => {
    const result = buildSmtpAuth('basic', { username: '', password: 'mypassword' });
    expect(result).toBeUndefined();
  });
});

// ==========================================================================
// buildSmtpAuth — Security
// ==========================================================================

describe('buildSmtpAuth — security', () => {
  it('should only expose the expected keys in the returned OAuth2 object', () => {
    const result = buildSmtpAuth('oauth2', {
      oauthUser: 'user@example.com',
      oauthClientId: 'client-id',
      oauthClientSecret: 'super-secret',
      oauthAccessToken: 'super-token',
    });
    expect(Object.keys(result ?? {})).toStrictEqual(['type', 'user', 'clientId', 'clientSecret', 'accessToken']);
  });
});
