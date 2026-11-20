import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('openid-client', () => ({
  discovery: vi.fn(async () => ({})),
  refreshTokenGrant: vi.fn(async () => ({ access_token: 'refreshed-access-token', expires_in: 3600 })),
}));

const mocks = vi.hoisted(() => ({
  createTransport: vi.fn((_options: Record<string, any>) => ({ verify: async () => true, sendMail: async () => ({ messageId: 'stub' }) })),
  getSmtpConfiguration: vi.fn(async (): Promise<Record<string, unknown> | null> => null),
  warn: vi.fn(),
}));

vi.mock('nodemailer', () => ({ default: { createTransport: mocks.createTransport } }));

vi.mock('../../../src/config/tracing', () => ({ meterManager: { emailSent: vi.fn() } }));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({ platform_title: 'OpenCTI', platform_email: 'platform@example.com' })),
}));

vi.mock('../../../src/modules/smtpConfiguration/smtpConfiguration-domain', () => ({
  getSmtpConfiguration: mocks.getSmtpConfiguration,
  smtpConfigurationRefreshTokenUpdate: vi.fn(),
}));

vi.mock('../../../src/modules/smtpConfiguration/smtpConfiguration-crypto', () => ({
  decryptSmtpSecret: vi.fn(async (value: string | null | undefined) => value),
}));

const FILE_BASIC_CREDENTIALS = { 'smtp:username': 'user', 'smtp:password': 'secret' };
const FILE_OAUTH2_CREDENTIALS = {
  'smtp:auth_type': 'oauth2',
  'smtp:oauth_user': 'mailbox@example.com',
  'smtp:oauth_client_id': 'client-id',
  'smtp:oauth_client_secret': 'client-secret',
  'smtp:oauth_issuer': 'https://idp.example.com',
  'smtp:oauth_refresh_token': 'refresh-token',
};

// SMTP options from the configuration file are read once, when the module is loaded:
// reload it with the given global TLS default and smtp configuration.
const loadSmtp = async (tlsRejectUnauthorized: boolean, smtpConfig: Record<string, unknown> = {}) => {
  vi.resetModules();
  vi.doMock('../../../src/config/conf', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../src/config/conf')>();
    const config: Record<string, unknown> = { 'smtp:enabled': true, 'smtp:use_ssl': false, ...smtpConfig };
    // smtp keys only come from the test configuration, whatever the local configuration files contain
    const isSmtpKey = (key: string) => key.startsWith('smtp:');
    return {
      ...actual,
      TLS_REJECT_UNAUTHORIZED: tlsRejectUnauthorized,
      default: { ...actual.default, get: (key: string) => (isSmtpKey(key) ? config[key] : actual.default.get(key)) },
      booleanConf: (key: string, defaultValue: boolean) => {
        if (!isSmtpKey(key)) return actual.booleanConf(key, defaultValue);
        return key in config ? config[key] : defaultValue;
      },
      logApp: { ...actual.logApp, info: vi.fn(), warn: mocks.warn },
    };
  });
  return import('../../../src/database/smtp');
};

type Smtp = Awaited<ReturnType<typeof loadSmtp>>;

// The three paths that build a transport
const TRANSPORT_PATHS: [string, (smtp: Smtp) => Promise<unknown>][] = [
  ['smtpIsAlive', (smtp) => smtp.smtpIsAlive()],
  ['sendMail', (smtp) => smtp.sendMail({ from: 'f', to: 't', bcc: '', subject: 's', html: 'h', attachments: [] }, {})],
  ['smtpTest', (smtp) => smtp.smtpTest('rcpt@example.com')],
];

const transportOptions = async (tlsRejectUnauthorized: boolean, smtpConfig: Record<string, unknown> = {}, path = TRANSPORT_PATHS[0][1]) => {
  mocks.createTransport.mockClear();
  const smtp = await loadSmtp(tlsRejectUnauthorized, smtpConfig);
  await path(smtp);
  return mocks.createTransport.mock.calls[0][0];
};

const securityWarnings = async (tlsRejectUnauthorized: boolean, smtpConfig: Record<string, unknown> = {}) => {
  mocks.warn.mockClear();
  const { checkSmtpSecurity } = await loadSmtp(tlsRejectUnauthorized, smtpConfig);
  await checkSmtpSecurity();
  return mocks.warn.mock.calls.map(([message]) => String(message));
};

const dbConfig = (config: Record<string, unknown> = {}) => ({
  use_db_config: true,
  smtp_enabled: true,
  hostname: 'smtp.company.com',
  port: 587,
  use_ssl: false,
  auth_type: 'basic',
  username: 'user',
  password_encrypted: 'secret',
  ...config,
});

const DB_OAUTH2_CREDENTIALS = {
  auth_type: 'oauth2',
  username: null,
  password_encrypted: null,
  oauth_user: 'mailbox@example.com',
  oauth_client_id: 'client-id',
  oauth_client_secret_encrypted: 'client-secret',
  oauth_issuer: 'https://idp.example.com',
  oauth_refresh_token_encrypted: 'refresh-token',
};

describe('SMTP requireTLS — configuration file', () => {
  beforeEach(() => {
    mocks.getSmtpConfiguration.mockResolvedValue(null);
  });

  it('should follow tls:reject_unauthorized when smtp:require_tls is not set', async () => {
    expect(await transportOptions(true, FILE_BASIC_CREDENTIALS)).toMatchObject({ secure: false, requireTLS: true });
    expect(await transportOptions(false, FILE_BASIC_CREDENTIALS)).toMatchObject({ secure: false, requireTLS: false });
  });

  it('should let smtp:require_tls override tls:reject_unauthorized', async () => {
    expect(await transportOptions(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:require_tls': true })).toMatchObject({ requireTLS: true });
    expect(await transportOptions(true, { ...FILE_BASIC_CREDENTIALS, 'smtp:require_tls': false })).toMatchObject({ requireTLS: false });
  });

  it.each(TRANSPORT_PATHS)('should require TLS on the %s transport', async (_name, path) => {
    expect(await transportOptions(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:require_tls': true }, path)).toMatchObject({ requireTLS: true });
  });

  it('should require TLS for an OAuth2 token', async () => {
    const options = await transportOptions(false, { ...FILE_OAUTH2_CREDENTIALS, 'smtp:require_tls': true });
    expect(options.auth).toMatchObject({ type: 'OAuth2' });
    expect(options).toMatchObject({ secure: false, requireTLS: true });
  });

  it('should not set requireTLS without credentials', async () => {
    const options = await transportOptions(false, { 'smtp:require_tls': true });
    expect(options.auth).toBeUndefined();
    expect(options.requireTLS).toBeUndefined();
  });

  it('should not set requireTLS with use_ssl, the connection being already encrypted', async () => {
    const withCredentials = await transportOptions(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:use_ssl': true, 'smtp:require_tls': true });
    expect(withCredentials).toMatchObject({ secure: true });
    expect(withCredentials.requireTLS).toBeUndefined();
    const withoutCredentials = await transportOptions(false, { 'smtp:use_ssl': true, 'smtp:require_tls': true });
    expect(withoutCredentials).toMatchObject({ secure: true });
    expect(withoutCredentials.requireTLS).toBeUndefined();
  });
});

describe('SMTP requireTLS — database configuration', () => {
  it('should follow tls:reject_unauthorized when require_tls is not stored', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig());
    expect(await transportOptions(true)).toMatchObject({ host: 'smtp.company.com', secure: false, requireTLS: true });
    expect(await transportOptions(false)).toMatchObject({ host: 'smtp.company.com', secure: false, requireTLS: false });
  });

  it('should use the stored require_tls over tls:reject_unauthorized', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: true }));
    expect(await transportOptions(false)).toMatchObject({ requireTLS: true });
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: false }));
    expect(await transportOptions(true)).toMatchObject({ requireTLS: false });
  });

  it('should ignore smtp:require_tls from the configuration file', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: false }));
    expect(await transportOptions(true, { 'smtp:require_tls': true })).toMatchObject({ requireTLS: false });
  });

  it.each(TRANSPORT_PATHS)('should require TLS on the %s transport', async (_name, path) => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: true }));
    expect(await transportOptions(false, {}, path)).toMatchObject({ requireTLS: true });
  });

  it('should require TLS for an OAuth2 token', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ ...DB_OAUTH2_CREDENTIALS, require_tls: true }));
    const options = await transportOptions(false);
    expect(options.auth).toMatchObject({ type: 'OAuth2' });
    expect(options).toMatchObject({ secure: false, requireTLS: true });
  });

  it('should not set requireTLS without credentials', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: true, username: null, password_encrypted: null }));
    const options = await transportOptions(false);
    expect(options.auth).toBeUndefined();
    expect(options.requireTLS).toBeUndefined();
  });

  it('should not set requireTLS with use_ssl, the connection being already encrypted', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ use_ssl: true, require_tls: true }));
    const withCredentials = await transportOptions(false);
    expect(withCredentials).toMatchObject({ secure: true });
    expect(withCredentials.requireTLS).toBeUndefined();
    mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ use_ssl: true, require_tls: true, username: null, password_encrypted: null }));
    const withoutCredentials = await transportOptions(false);
    expect(withoutCredentials).toMatchObject({ secure: true });
    expect(withoutCredentials.requireTLS).toBeUndefined();
  });
});

describe('checkSmtpSecurity', () => {
  const CLEARTEXT = 'SMTP credentials may be sent over an unencrypted connection';
  const UNVERIFIED = 'SMTP server certificate is not verified';

  describe('configuration file', () => {
    beforeEach(() => {
      mocks.getSmtpConfiguration.mockResolvedValue(null);
    });

    it('should warn when STARTTLS is not required, with the configuration key', async () => {
      const [warning] = await securityWarnings(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:require_tls': false });
      expect(warning).toContain(CLEARTEXT);
      expect(warning).toContain('smtp:require_tls=false');
      expect(warning).toContain('SMTP__REQUIRE_TLS=true');
    });

    it('should warn for an OAuth2 token', async () => {
      const [warning] = await securityWarnings(false, { ...FILE_OAUTH2_CREDENTIALS, 'smtp:require_tls': false });
      expect(warning).toContain(CLEARTEXT);
    });

    it('should warn when STARTTLS is required but the certificate is not verified', async () => {
      const [warning] = await securityWarnings(true, { ...FILE_BASIC_CREDENTIALS, 'smtp:reject_unauthorized': false });
      expect(warning).toContain(UNVERIFIED);
      expect(warning).toContain('smtp:reject_unauthorized=false');
    });

    it('should warn when use_ssl is set but the certificate is not verified', async () => {
      const [warning] = await securityWarnings(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:use_ssl': true });
      expect(warning).toContain(UNVERIFIED);
    });

    it('should not warn when the credentials are protected', async () => {
      expect(await securityWarnings(true, FILE_BASIC_CREDENTIALS)).toEqual([]);
      expect(await securityWarnings(true, { ...FILE_BASIC_CREDENTIALS, 'smtp:use_ssl': true })).toEqual([]);
    });

    it('should not warn without credentials or when SMTP is disabled', async () => {
      expect(await securityWarnings(false)).toEqual([]);
      expect(await securityWarnings(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:enabled': false })).toEqual([]);
    });
  });

  describe('database configuration', () => {
    it('should warn when STARTTLS is not required, with the interface option', async () => {
      mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: false }));
      const [warning] = await securityWarnings(true, { 'smtp:require_tls': true });
      expect(warning).toContain(CLEARTEXT);
      expect(warning).toContain('"Require STARTTLS" disabled in the SMTP configuration interface');
      expect(warning).not.toContain('SMTP__REQUIRE_TLS');
    });

    it('should warn for an OAuth2 token', async () => {
      mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ ...DB_OAUTH2_CREDENTIALS, require_tls: false }));
      const [warning] = await securityWarnings(true);
      expect(warning).toContain(CLEARTEXT);
    });

    it('should warn when STARTTLS is required but the certificate is not verified', async () => {
      mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: true, reject_unauthorized: false }));
      const [warning] = await securityWarnings(true);
      expect(warning).toContain(UNVERIFIED);
      expect(warning).toContain('"Reject unauthorized certificates" disabled in the SMTP configuration interface');
    });

    it('should not warn when the credentials are protected, without credentials, or when SMTP is disabled', async () => {
      mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: true, reject_unauthorized: true }));
      expect(await securityWarnings(false, { 'smtp:require_tls': false })).toEqual([]);
      mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: false, username: null, password_encrypted: null }));
      expect(await securityWarnings(false)).toEqual([]);
      mocks.getSmtpConfiguration.mockResolvedValue(dbConfig({ require_tls: false, smtp_enabled: false }));
      expect(await securityWarnings(false)).toEqual([]);
    });
  });

  it('should not warn from smtpIsAlive, which runs before the database configuration can be read', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(null);
    mocks.warn.mockClear();
    await transportOptions(false, { ...FILE_BASIC_CREDENTIALS, 'smtp:require_tls': false });
    expect(mocks.warn).not.toHaveBeenCalled();
  });
});

describe('smtpIsAlive', () => {
  it('should log the cause when the server cannot be reached, such as a refused STARTTLS', async () => {
    mocks.getSmtpConfiguration.mockResolvedValue(null);
    mocks.warn.mockClear();
    const error = new Error('Can\'t send mail - no STARTTLS support');
    const verify = async () => {
      throw error;
    };
    mocks.createTransport.mockReturnValueOnce({ verify, sendMail: async () => ({ messageId: 'stub' }) });
    const { smtpIsAlive } = await loadSmtp(false, FILE_BASIC_CREDENTIALS);
    await smtpIsAlive();
    expect(mocks.warn).toHaveBeenCalledWith('SMTP seems down, email notification may not work', { cause: error });
  });
});
