import { beforeEach, describe, expect, it, vi } from 'vitest';

// `openid-client` performs an HTTP discovery + token exchange that we don't
// want to run during unit tests — stub it so OAuth2 tests stay hermetic.
vi.mock('openid-client', () => ({
  discovery: vi.fn(async () => ({})),
  refreshTokenGrant: vi.fn(async () => ({ access_token: 'refreshed-access-token', expires_in: 3600 })),
}));

import { __resetSmtpCachesForTests, buildSmtpAuth as buildSmtpAuthImpl } from '../../../src/database/smtp';

type SmtpCredentials = {
  username?: string;
  password?: string;
  oauthUser?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthIssuer?: string;
  oauthRefreshToken?: string;
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
    oauthIssuer: 'https://login.example.com/v2.0',
    oauthRefreshToken: 'my-refresh-token',
  };

  beforeEach(async () => {
    __resetSmtpCachesForTests();
    const { discovery, refreshTokenGrant } = await import('openid-client');
    (discovery as unknown as ReturnType<typeof vi.fn>).mockClear();
    (refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).mockClear();
  });

  it('should return an OAuth2 auth object with a refreshed access token', async () => {
    const result = await buildSmtpAuth('oauth2', oauth2Config);
    expect(result).toStrictEqual({
      type: 'OAuth2',
      user: 'user@example.com',
      clientId: 'my-client-id',
      clientSecret: 'my-client-secret',
      accessToken: 'refreshed-access-token',
    });
  });

  it('should use oauthUser and not username even when both are provided', async () => {
    const result = await buildSmtpAuth('oauth2', {
      ...oauth2Config,
      username: 'legacy@example.com',
      password: 'legacy-pass',
    });
    expect(result).toHaveProperty('type', 'OAuth2');
    expect(result).toHaveProperty('user', 'user@example.com');
    expect(result).not.toHaveProperty('pass');
  });

  it('should throw an error when oauth_* required fields are missing', async () => {
    await expect(buildSmtpAuth('oauth2', {})).rejects.toThrow(
      'SMTP OAuth2 configuration is incomplete: oauth_user, oauth_client_id, oauth_client_secret, oauth_issuer and oauth_refresh_token are all required.',
    );
  });

  it('should throw an error when only some oauth_* fields are provided', async () => {
    await expect(buildSmtpAuth('oauth2', { oauthUser: 'user@example.com' })).rejects.toThrow(
      'SMTP OAuth2 configuration is incomplete',
    );
  });

  it('should work with any OIDC-compliant issuer URL (provider-agnostic)', async () => {
    const result = await buildSmtpAuth('oauth2', {
      oauthUser: 'user@example.com',
      oauthClientId: 'my-client-id',
      oauthClientSecret: 'my-client-secret',
      oauthIssuer: 'https://accounts.google.com',
      oauthRefreshToken: 'my-refresh-token',
    });
    expect(result).toHaveProperty('type', 'OAuth2');
    expect(result).toHaveProperty('accessToken', 'refreshed-access-token');
  });

  it('should wrap refresh failures in a clear error message', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    (refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('boom'));
    await expect(buildSmtpAuth('oauth2', oauth2Config)).rejects.toThrow(
      'Unable to refresh SMTP OAuth2 access token: boom',
    );
  });

  it('should cache the access token and skip refresh on subsequent calls within the validity window', async () => {
    const { discovery, refreshTokenGrant } = await import('openid-client');
    await buildSmtpAuth('oauth2', oauth2Config);
    await buildSmtpAuth('oauth2', oauth2Config);
    await buildSmtpAuth('oauth2', oauth2Config);
    // OIDC discovery happens once, refresh token grant happens once for three sends.
    expect(discovery as unknown as ReturnType<typeof vi.fn>).toHaveBeenCalledTimes(1);
    expect(refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).toHaveBeenCalledTimes(1);
  });

  it('should coalesce concurrent refresh attempts into a single network call', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    const results = await Promise.all([
      buildSmtpAuth('oauth2', oauth2Config),
      buildSmtpAuth('oauth2', oauth2Config),
      buildSmtpAuth('oauth2', oauth2Config),
      buildSmtpAuth('oauth2', oauth2Config),
      buildSmtpAuth('oauth2', oauth2Config),
    ]);
    expect(refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).toHaveBeenCalledTimes(1);
    results.forEach((result) => expect(result).toHaveProperty('accessToken', 'refreshed-access-token'));
  });

  it('should throw a dedicated error when the IdP returns no access_token', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    (refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ expires_in: 3600 });
    await expect(buildSmtpAuth('oauth2', oauth2Config)).rejects.toThrow(
      'Unable to refresh SMTP OAuth2 access token: refresh token grant did not return an access_token',
    );
  });

  it('should preserve the original error as the cause when refresh fails', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    const originalError = new Error('network down');
    (refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(originalError);
    await expect(buildSmtpAuth('oauth2', oauth2Config)).rejects.toMatchObject({
      message: 'Unable to refresh SMTP OAuth2 access token: network down',
      cause: originalError,
    });
  });

  it('should clear the in-flight refresh after a failure so the next call can retry', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    const refreshMock = refreshTokenGrant as unknown as ReturnType<typeof vi.fn>;
    refreshMock.mockRejectedValueOnce(new Error('transient'));
    await expect(buildSmtpAuth('oauth2', oauth2Config)).rejects.toThrow('transient');
    // After a rejected refresh, a subsequent call must perform a new refresh (no stuck promise).
    const result = await buildSmtpAuth('oauth2', oauth2Config);
    expect(result).toHaveProperty('accessToken', 'refreshed-access-token');
    expect(refreshMock).toHaveBeenCalledTimes(2);
  });

  it('should re-refresh the access token after it expires and reuse the cached OIDC discovery', async () => {
    const { discovery, refreshTokenGrant } = await import('openid-client');
    const refreshMock = refreshTokenGrant as unknown as ReturnType<typeof vi.fn>;
    // 1s lifetime so the cache invalidates almost immediately.
    refreshMock.mockResolvedValueOnce({ access_token: 'token-1', expires_in: 1 });
    refreshMock.mockResolvedValueOnce({ access_token: 'token-2', expires_in: 3600 });

    const first = await buildSmtpAuth('oauth2', oauth2Config);
    expect(first).toHaveProperty('accessToken', 'token-1');

    // Force the cached token to look expired (5min margin → push 6min into the future).
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 6 * 60 * 1000);
    try {
      const second = await buildSmtpAuth('oauth2', oauth2Config);
      expect(second).toHaveProperty('accessToken', 'token-2');
    } finally {
      vi.useRealTimers();
    }

    expect(refreshMock).toHaveBeenCalledTimes(2);
    // OIDC discovery is reused across token refreshes — it must run only once.
    expect(discovery as unknown as ReturnType<typeof vi.fn>).toHaveBeenCalledTimes(1);
  });

  it('should default the token TTL to ~1h when the IdP omits expires_in', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    const refreshMock = refreshTokenGrant as unknown as ReturnType<typeof vi.fn>;
    // No expires_in → code path that falls back to a 3600s default.
    refreshMock.mockResolvedValueOnce({ access_token: 'token-no-ttl' });

    await buildSmtpAuth('oauth2', oauth2Config);
    // Subsequent calls within the default 1h window must hit the cache.
    await buildSmtpAuth('oauth2', oauth2Config);
    await buildSmtpAuth('oauth2', oauth2Config);
    expect(refreshMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['oauth_user', { ...{}, oauthClientId: 'c', oauthClientSecret: 's', oauthIssuer: 'i', oauthRefreshToken: 'r' }],
    ['oauth_client_id', { oauthUser: 'u', oauthClientSecret: 's', oauthIssuer: 'i', oauthRefreshToken: 'r' }],
    ['oauth_client_secret', { oauthUser: 'u', oauthClientId: 'c', oauthIssuer: 'i', oauthRefreshToken: 'r' }],
    ['oauth_issuer', { oauthUser: 'u', oauthClientId: 'c', oauthClientSecret: 's', oauthRefreshToken: 'r' }],
    ['oauth_refresh_token', { oauthUser: 'u', oauthClientId: 'c', oauthClientSecret: 's', oauthIssuer: 'i' }],
  ])('should reject when %s is missing', async (_field, partial) => {
    await expect(buildSmtpAuth('oauth2', partial as SmtpCredentials)).rejects.toThrow(
      /SMTP OAuth2 configuration is incomplete/,
    );
  });
});

// ==========================================================================
// buildSmtpAuth — Basic Auth
// ==========================================================================

describe('buildSmtpAuth — Basic Auth', () => {
  it('should return a Basic Auth object when authType is "basic" and username is set', async () => {
    const result = await buildSmtpAuth('basic', { username: 'user@example.com', password: 'mypassword' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: 'mypassword' });
  });

  it('should return a Basic Auth object when authType is not set (defaults to basic)', async () => {
    const result = await buildSmtpAuth(undefined, { username: 'user@example.com', password: 'mypassword' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: 'mypassword' });
  });

  it('should set pass to empty string when password is absent', async () => {
    const result = await buildSmtpAuth('basic', { username: 'user@example.com' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: '' });
  });

  it('should return undefined when username is absent', async () => {
    const result = await buildSmtpAuth('basic', {});
    expect(result).toBeUndefined();
  });

  it('should return undefined when username is an empty string', async () => {
    const result = await buildSmtpAuth('basic', { username: '', password: 'mypassword' });
    expect(result).toBeUndefined();
  });

  it('should return undefined when called with no credentials at all (default param)', async () => {
    // Exercises the default `= {}` destructuring branch of buildSmtpAuth.
    const result = await (buildSmtpAuthImpl as unknown as (a?: string) => Promise<unknown>)('basic');
    expect(result).toBeUndefined();
  });

  it('should treat unknown auth types as non-OAuth2 (basic fallback behaviour)', async () => {
    const result = await buildSmtpAuth('something-else', { username: 'user@example.com', password: 'p' });
    expect(result).toStrictEqual({ user: 'user@example.com', pass: 'p' });
  });

  it('should treat unknown auth types with no username as no-auth (undefined)', async () => {
    const result = await buildSmtpAuth('something-else', {});
    expect(result).toBeUndefined();
  });
});

// ==========================================================================
// buildSmtpAuth — Security
// ==========================================================================

describe('buildSmtpAuth — security', () => {
  it('should only expose the expected keys in the returned OAuth2 object', async () => {
    const result = await buildSmtpAuth('oauth2', {
      oauthUser: 'user@example.com',
      oauthClientId: 'client-id',
      oauthClientSecret: 'super-secret',
      oauthIssuer: 'https://login.example.com/v2.0',
      oauthRefreshToken: 'refresh-token',
    });
    expect(Object.keys(result ?? {})).toStrictEqual(['type', 'user', 'clientId', 'clientSecret', 'accessToken']);
  });
});
