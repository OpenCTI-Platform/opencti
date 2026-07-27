import { beforeEach, describe, expect, it, vi } from 'vitest';

// `openid-client` performs an HTTP discovery + token exchange that we don't
// want to run during unit tests — stub it so OAuth2 tests stay hermetic.
vi.mock('openid-client', () => ({
  discovery: vi.fn(async () => ({})),
  refreshTokenGrant: vi.fn(async () => ({ access_token: 'refreshed-access-token', expires_in: 3600 })),
}));

// Stub `nodemailer` so transporter creation/verify/sendMail are observable
// without opening real SMTP connections. `vi.hoisted` is required because
// `vi.mock` is hoisted to the top of the file — regular `const` would not be
// initialized when the factory runs.
const nodemailerMocks = vi.hoisted(() => {
  const verify = vi.fn(async () => true);
  const sendMail = vi.fn(async () => ({ messageId: 'stub' }));
  const createTransport = vi.fn(() => ({ verify, sendMail }));
  return { verify, sendMail, createTransport };
});
vi.mock('nodemailer', () => ({
  default: { createTransport: nodemailerMocks.createTransport },
}));

// Stub the cache lookup used by smtpComputeFrom so we don't need a live cache.
vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({
    platform_title: 'OpenCTI',
    platform_email: 'platform@example.com',
  })),
}));

// Stub `../config/conf` to guarantee deterministic SMTP module-level constants
// (auth_type, enabled, ...) regardless of the developer's local config files.
// Without this, a developer with `smtp.auth_type = "oauth2"` in their
// development.json would make createSmtpTransporter throw on missing fields
// before nodemailer.createTransport is invoked, breaking these tests.
// Partial mock: we keep everything else from the real conf module so the rest
// of the imported codebase keeps working (TEST_MODE, logger, etc.).
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  const smtpOverrides: Record<string, unknown> = {
    'smtp:enabled': true,
    'smtp:auth_type': 'basic',
    'smtp:use_ssl': false,
    'smtp:reject_unauthorized': false,
    'smtp:hostname': 'localhost',
    'smtp:port': 25,
    'smtp:username': '',
    'smtp:password': '',
    'smtp:forced_sender_email': '',
  };
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (key: string) => (key in smtpOverrides ? smtpOverrides[key] : (actual.default as { get: (k: string) => unknown }).get(key)),
    },
    booleanConf: (key: string, fallback: boolean) => {
      const value = smtpOverrides[key];
      if (typeof value === 'boolean') return value;
      return actual.booleanConf(key, fallback);
    },
  };
});

// Stub tracing to avoid pulling in the full telemetry stack.
vi.mock('../../../src/config/tracing', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/tracing')>();
  return {
    ...actual,
    meterManager: { ...actual.meterManager, emailSent: vi.fn() },
  };
});

// Stub the DB config lookup so smtp.js never hits Elasticsearch in unit tests.
// Default: no DB config (use_db_config: false / no row) → fall back to JSON config.
const smtpConfigurationDomainMocks = vi.hoisted(() => ({
  getSmtpConfiguration: vi.fn(async () => null),
  smtpConfigurationRefreshTokenUpdate: vi.fn(async () => undefined),
}));
vi.mock('../../../src/modules/smtpConfiguration/smtpConfiguration-domain', () => smtpConfigurationDomainMocks);

// Stub smtpConfiguration-crypto so decryptSmtpSecret is a no-op in unit tests
// (passes the value through unchanged so auth logic is still exercised).
vi.mock('../../../src/modules/smtpConfiguration/smtpConfiguration-crypto', () => ({
  decryptSmtpSecret: vi.fn(async (v: string | null | undefined) => v),
}));

import {
  __resetSmtpCachesForTests,
  buildSmtpAuth as buildSmtpAuthImpl,
  isEmailRewriteAllowed,
  sendMail,
  smtpComputeFrom,
  smtpConfiguredEmail,
  smtpIsAlive,
  smtpTest,
} from '../../../src/database/smtp';

type SmtpCredentials = {
  username?: string;
  password?: string;
  oauthUser?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthIssuer?: string;
  oauthRefreshToken?: string;
  onRefreshToken?: (newRefreshToken: string, previousRefreshToken: string) => Promise<void>;
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

  it('should report a rotated refresh token returned by the identity provider', async () => {
    const { refreshTokenGrant } = await import('openid-client');
    (refreshTokenGrant as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
      expires_in: 3600,
    });
    const onRefreshToken = vi.fn(async () => undefined);

    await buildSmtpAuth('oauth2', { ...oauth2Config, onRefreshToken });

    expect(onRefreshToken).toHaveBeenCalledWith('new-refresh-token', 'my-refresh-token');
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

// ==========================================================================
// smtpConfiguredEmail
// ==========================================================================

describe('smtpConfiguredEmail', () => {
  beforeEach(() => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue(null);
  });

  it('should return the platform email when no DB config and no forced sender', async () => {
    const settings = { platform_email: 'platform@example.com' } as unknown as { platform_email: string };
    expect(await smtpConfiguredEmail(settings)).toBe('platform@example.com');
  });

  it('should return sender_email_address from DB when use_db_config is true and address is set', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValueOnce({
      use_db_config: true,
      sender_email_address: 'smtp-db@example.com',
    } as any);
    expect(await smtpConfiguredEmail({ platform_email: 'platform@example.com' })).toBe('smtp-db@example.com');
  });

  it('should fall back to platform_email when DB config is active but sender_email_address is not set', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValueOnce({
      use_db_config: true,
      sender_email_address: undefined,
    } as any);
    expect(await smtpConfiguredEmail({ platform_email: 'platform@example.com' })).toBe('platform@example.com');
  });
});

// ==========================================================================
// smtpComputeFrom
// ==========================================================================

describe('smtpComputeFrom', () => {
  beforeEach(() => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue(null);
  });

  it('should format the From header with the provided sender name and platform email', async () => {
    const result = await smtpComputeFrom('Acme Notifications');
    expect(result).toBe('Acme Notifications <platform@example.com>');
  });

  it('should fall back to platform_title when no sender name is provided', async () => {
    const result = await smtpComputeFrom();
    expect(result).toBe('OpenCTI <platform@example.com>');
  });
});

// ==========================================================================
// createSmtpTransporter (covered indirectly via smtpIsAlive / sendMail)
// ==========================================================================

describe('createSmtpTransporter — DB vs JSON config, sendMail, smtpIsAlive', () => {
  const { createTransport: nodemailerCreateTransport, verify: nodemailerVerify, sendMail: nodemailerSendMail } = nodemailerMocks;

  beforeEach(() => {
    __resetSmtpCachesForTests();
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue(null);
    nodemailerCreateTransport.mockClear();
    nodemailerVerify.mockClear();
    nodemailerSendMail.mockClear();
  });

  it('smtpIsAlive should call transporter.verify and log success when SMTP is reachable', async () => {
    nodemailerVerify.mockResolvedValueOnce(true);
    const result = await smtpIsAlive();
    expect(result).toBe(true);
    expect(nodemailerCreateTransport).toHaveBeenCalledTimes(1);
    expect(nodemailerVerify).toHaveBeenCalledTimes(1);
  });

  it('smtpIsAlive should swallow transporter.verify errors and still return true', async () => {
    nodemailerVerify.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));
    const result = await smtpIsAlive();
    expect(result).toBe(true);
    expect(nodemailerVerify).toHaveBeenCalledTimes(1);
  });

  it('sendMail should build a transporter and forward the message fields to nodemailer', async () => {
    await sendMail(
      {
        from: 'Sender <sender@example.com>',
        to: 'rcpt@example.com',
        bcc: 'bcc@example.com',
        subject: 'Hello',
        html: '<p>Hi</p>',
        attachments: [],
      },
      { kind: 'test' },
    );
    expect(nodemailerSendMail).toHaveBeenCalledTimes(1);
    expect(nodemailerSendMail).toHaveBeenCalledWith({
      from: 'Sender <sender@example.com>',
      to: 'rcpt@example.com',
      bcc: 'bcc@example.com',
      subject: 'Hello',
      html: '<p>Hi</p>',
      attachments: [],
    });
  });

  it('should create a new transporter on every call (no caching)', async () => {
    await sendMail({ from: 'f', to: 't', bcc: '', subject: 's', html: 'h', attachments: [] }, {});
    await sendMail({ from: 'f', to: 't', bcc: '', subject: 's', html: 'h', attachments: [] }, {});
    await smtpIsAlive();
    expect(nodemailerCreateTransport).toHaveBeenCalledTimes(3);
  });

  it('should use JSON config options when use_db_config is false', async () => {
    await smtpIsAlive();
    // The conf mock sets hostname to 'localhost', port to 25 — verify those are passed.
    const callOptions = (nodemailerCreateTransport.mock.calls[0] as any[])[0];
    expect(callOptions).toMatchObject({ host: 'localhost', port: 25, secure: false });
  });

  it('should use DB hostname and port when use_db_config is true', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue({
      use_db_config: true,
      smtp_enabled: true,
      hostname: 'smtp.company.com',
      port: 587,
      use_ssl: true,
      reject_unauthorized: true,
      auth_type: 'basic',
      username: 'user',
      password_encrypted: 'encrypted-pass',
    } as any);
    await smtpIsAlive();
    const callOptions = (nodemailerCreateTransport.mock.calls[0] as any[])[0];
    expect(callOptions).toMatchObject({ host: 'smtp.company.com', port: 587, secure: true });
    expect(callOptions.tls).toMatchObject({ rejectUnauthorized: true });
  });

  it('should decrypt password_encrypted when using DB config and pass plaintext to nodemailer auth', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue({
      use_db_config: true,
      smtp_enabled: true,
      hostname: 'smtp.company.com',
      port: 587,
      auth_type: 'basic',
      username: 'user@company.com',
      password_encrypted: 'c29tZWVuY3J5cHRlZGRhdGE=', // any non-empty base64 string
    } as any);
    await smtpIsAlive();
    // Verify decryption was wired: nodemailer auth.pass must be a string (decryptSmtpSecret ran)
    const callOptions = (nodemailerCreateTransport.mock.calls[0] as any[])[0];
    expect(callOptions.auth).toHaveProperty('user', 'user@company.com');
    expect(typeof callOptions.auth.pass).toBe('string');
  });

  it('should not send and not call createTransport when smtp_enabled is false in DB', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue({
      use_db_config: true,
      smtp_enabled: false,
    } as any);
    await sendMail({ from: 'f', to: 't', bcc: '', subject: 's', html: 'h', attachments: [] }, {});
    expect(nodemailerCreateTransport).not.toHaveBeenCalled();
    expect(nodemailerSendMail).not.toHaveBeenCalled();
  });

  it('should not verify and skip SMTP check when smtp_enabled is false in DB', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue({
      use_db_config: true,
      smtp_enabled: false,
    } as any);
    const result = await smtpIsAlive();
    expect(result).toBe(true);
    expect(nodemailerVerify).not.toHaveBeenCalled();
  });
});

// ==========================================================================
// smtpTest
// ==========================================================================

describe('smtpTest', () => {
  const { createTransport: nodemailerCreateTransport, sendMail: nodemailerSendMail } = nodemailerMocks;

  beforeEach(() => {
    __resetSmtpCachesForTests();
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue(null);
    nodemailerCreateTransport.mockClear();
    nodemailerSendMail.mockClear();
  });

  it('should send an email to the provided address and return true', async () => {
    const result = await smtpTest('admin@example.com');
    expect(result).toBe(true);
    expect(nodemailerSendMail).toHaveBeenCalledTimes(1);
    const call = (nodemailerSendMail.mock.calls[0] as any[])[0];
    expect(call.to).toBe('admin@example.com');
    expect(call.subject).toBe('OpenCTI SMTP Test');
    expect(call).toHaveProperty('from');
    expect(call).toHaveProperty('html');
  });

  it('should propagate errors thrown by nodemailer.sendMail', async () => {
    nodemailerSendMail.mockRejectedValueOnce(new Error('connection refused'));
    await expect(smtpTest('admin@example.com')).rejects.toThrow('connection refused');
  });
});

// ==========================================================================
// isEmailRewriteAllowed
// ==========================================================================

describe('isEmailRewriteAllowed', () => {
  beforeEach(() => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValue(null);
  });

  it('should return true when no DB config is active (JSON config with no forced sender email)', async () => {
    expect(await isEmailRewriteAllowed()).toBe(true);
  });

  it('should return false when DB config is active and sender_email_address is set', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValueOnce({
      use_db_config: true,
      sender_email_address: 'fixed@company.com',
    } as any);
    expect(await isEmailRewriteAllowed()).toBe(false);
  });

  it('should return true when DB config is active but sender_email_address is not set', async () => {
    smtpConfigurationDomainMocks.getSmtpConfiguration.mockResolvedValueOnce({
      use_db_config: true,
      sender_email_address: undefined,
    } as any);
    expect(await isEmailRewriteAllowed()).toBe(true);
  });
});
