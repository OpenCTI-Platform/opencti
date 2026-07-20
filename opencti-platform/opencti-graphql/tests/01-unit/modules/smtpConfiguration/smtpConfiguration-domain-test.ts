import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Middleware from '../../../../src/database/middleware';
import * as Conf from '../../../../src/config/conf';
import {
  getSmtpConfiguration,
  getSmtpConfigurationForAdmin,
  smtpConfigurationDelete,
  smtpConfigurationEdit,
  smtpConfigurationTest,
} from '../../../../src/modules/smtpConfiguration/smtpConfiguration-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/database/smtp', () => ({
  smtpTest: vi.fn(async () => true),
  ALLOW_EMAIL_REWRITE: true,
}));

vi.mock('../../../../src/modules/smtpConfiguration/smtpConfiguration-crypto', () => ({
  encryptSmtpSecret: vi.fn(async (v: string | null | undefined) => (v ? `encrypted:${v}` : v)),
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn().mockImplementation((_, element) => Promise.resolve(element)),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    BUS_TOPICS: {
      Settings: {
        EDIT_TOPIC: 'SETTINGS_EDIT_TOPIC',
      },
    },
    isFeatureEnabled: vi.fn(() => true),
  };
});

const mockContext = { source: 'testing' } as any;
const mockUser = SYSTEM_USER;

const MOCK_SMTP_CONFIG = {
  smtp_enabled: false,
  use_db_config: false,
  forced_sender_email: false,
  hostname: 'smtp.example.com',
  port: 587,
};

const MOCK_SMTP_CONFIG_STORED = {
  smtp_enabled: false,
  use_db_config: false,
  hostname: 'smtp.example.com',
  port: 587,
};

const MOCK_SETTINGS = {
  id: 'settings-id-123',
  entity_type: 'Settings',
  smtp_configuration: MOCK_SMTP_CONFIG_STORED,
} as any;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(Conf.isFeatureEnabled).mockReturnValue(true);
  vi.mocked(Cache.getEntityFromCache).mockResolvedValue(MOCK_SETTINGS);
});

// ---------- feature flag disabled ----------

describe('feature flag disabled', () => {
  beforeEach(() => {
    vi.mocked(Conf.isFeatureEnabled).mockReturnValue(false);
  });

  it('smtpConfigurationEdit should throw ForbiddenAccess', async () => {
    await expect(smtpConfigurationEdit(mockContext, mockUser, { smtp_enabled: false, use_db_config: false }))
      .rejects.toMatchObject({ extensions: { code: 'FORBIDDEN_ACCESS' } });
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('smtpConfigurationTest should throw ForbiddenAccess', async () => {
    await expect(smtpConfigurationTest(mockContext, mockUser, 'test@example.com'))
      .rejects.toMatchObject({ extensions: { code: 'FORBIDDEN_ACCESS' } });
  });

  it('getSmtpConfigurationForAdmin should throw ForbiddenAccess', async () => {
    await expect(getSmtpConfigurationForAdmin(mockContext, mockUser))
      .rejects.toMatchObject({ extensions: { code: 'FORBIDDEN_ACCESS' } });
    expect(Cache.getEntityFromCache).not.toHaveBeenCalled();
  });
});

// ---------- getSmtpConfiguration ----------

describe('getSmtpConfiguration', () => {
  it('should return the smtp_configuration from settings', async () => {
    const result = await getSmtpConfiguration(mockContext, mockUser);
    expect(result).toEqual(MOCK_SMTP_CONFIG);
    expect(Cache.getEntityFromCache).toHaveBeenCalledOnce();
  });

  it('should return null when settings has no smtp_configuration', async () => {
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue({ ...MOCK_SETTINGS, smtp_configuration: undefined });
    const result = await getSmtpConfiguration(mockContext, mockUser);
    expect(result).toBeNull();
  });
});

// ---------- getSmtpConfigurationForAdmin ----------

describe('getSmtpConfigurationForAdmin', () => {
  it('should delegate to getSmtpConfiguration when feature is enabled', async () => {
    const result = await getSmtpConfigurationForAdmin(mockContext, mockUser);
    expect(result).toEqual(MOCK_SMTP_CONFIG);
    expect(Cache.getEntityFromCache).toHaveBeenCalledOnce();
  });

  it('should return null when settings has no smtp_configuration', async () => {
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue({ ...MOCK_SETTINGS, smtp_configuration: undefined });
    const result = await getSmtpConfigurationForAdmin(mockContext, mockUser);
    expect(result).toBeNull();
  });
});

// ---------- smtpConfigurationEdit ----------

describe('smtpConfigurationEdit', () => {
  const updatedSettings = {
    ...MOCK_SETTINGS,
    smtp_configuration: { ...MOCK_SMTP_CONFIG, hostname: 'updated.example.com', smtp_enabled: true },
  };

  beforeEach(() => {
    vi.mocked(Middleware.patchAttribute).mockResolvedValue({ element: updatedSettings } as any);
  });

  it('should patch settings with smtp_configuration and return it', async () => {
    const result = await smtpConfigurationEdit(mockContext, mockUser, {
      smtp_enabled: true,
      use_db_config: false,
      hostname: 'updated.example.com',
      port: 587,
    });
    expect(result).toEqual(updatedSettings.smtp_configuration);
    expect(Middleware.patchAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      MOCK_SETTINGS.id,
      'Settings',
      expect.objectContaining({ smtp_configuration: expect.any(Object) }),
    );
  });

  it('should wrap input in smtp_configuration key when calling patchAttribute', async () => {
    await smtpConfigurationEdit(mockContext, mockUser, { smtp_enabled: true, use_db_config: false, port: 587 });
    const patch = (vi.mocked(Middleware.patchAttribute).mock.calls[0] as any[])[4];
    expect(patch).toHaveProperty('smtp_configuration');
    expect(Object.keys(patch)).toEqual(['smtp_configuration']);
  });

  it('should reject port 25', async () => {
    await expect(smtpConfigurationEdit(mockContext, mockUser, { port: 25 }))
      .rejects.toThrow('Port 25 is not allowed for SMTP configuration');
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('should reject basic auth without username or password', async () => {
    await expect(smtpConfigurationEdit(mockContext, mockUser, { auth_type: 'basic' as any, username: 'user' }))
      .rejects.toThrow('username and password are required for basic authentication');
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('should reject oauth2 without required fields', async () => {
    await expect(smtpConfigurationEdit(mockContext, mockUser, { auth_type: 'oauth2' as any, oauth_client_id: 'id' }))
      .rejects.toThrow('oauth_client_id, oauth_client_secret and oauth_issuer are required for OAuth2 authentication');
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('should encrypt secrets before storing', async () => {
    await smtpConfigurationEdit(mockContext, mockUser, {
      smtp_enabled: true,
      use_db_config: true,
      auth_type: 'basic' as any,
      username: 'user',
      password: 'secret-password',
    });
    const patch = (vi.mocked(Middleware.patchAttribute).mock.calls[0] as any[])[4];
    const storedConfig = patch.smtp_configuration;
    expect(storedConfig).not.toHaveProperty('password');
    expect(storedConfig).toHaveProperty('password_encrypted');
    expect(storedConfig.password_encrypted).toBe('encrypted:secret-password');
  });

  it('should drop oauth_access_token from stored input', async () => {
    await smtpConfigurationEdit(mockContext, mockUser, {
      smtp_enabled: true,
      use_db_config: true,
      oauth_access_token: 'ephemeral-token',
    });
    const patch = (vi.mocked(Middleware.patchAttribute).mock.calls[0] as any[])[4];
    expect(patch.smtp_configuration).not.toHaveProperty('oauth_access_token');
  });

  it('should not include secrets in publishUserAction audit log', async () => {
    const { publishUserAction } = await import('../../../../src/listener/UserActionListener');
    await smtpConfigurationEdit(mockContext, mockUser, {
      hostname: 'smtp.example.com',
      password: 'secret',
      oauth_client_secret: 'oauth-secret',
    });
    const call = vi.mocked(publishUserAction).mock.calls[0][0];
    const contextData = call.context_data as { input: Record<string, unknown> };
    expect(contextData.input).toHaveProperty('hostname');
    expect(contextData.input).not.toHaveProperty('password');
    expect(contextData.input).not.toHaveProperty('password_encrypted');
    expect(contextData.input).not.toHaveProperty('oauth_client_secret');
    expect(contextData.input).not.toHaveProperty('oauth_client_secret_encrypted');
  });
});

// ---------- smtpConfigurationDelete ----------

describe('smtpConfigurationDelete', () => {
  beforeEach(() => {
    vi.mocked(Middleware.patchAttribute).mockResolvedValue({ element: MOCK_SETTINGS } as any);
  });

  it('should patch smtp_configuration to null and return true', async () => {
    const result = await smtpConfigurationDelete(mockContext, mockUser);
    expect(result).toBe(true);
    expect(Middleware.patchAttribute).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      MOCK_SETTINGS.id,
      'Settings',
      { smtp_configuration: null },
    );
  });

  it('should publish a delete audit log', async () => {
    const { publishUserAction } = await import('../../../../src/listener/UserActionListener');
    await smtpConfigurationDelete(mockContext, mockUser);
    expect(vi.mocked(publishUserAction)).toHaveBeenCalledWith(
      expect.objectContaining({ event_scope: 'delete', event_access: 'administration' }),
    );
  });

  it('should throw ForbiddenAccess when feature flag is disabled', async () => {
    vi.mocked(Conf.isFeatureEnabled).mockReturnValue(false);
    await expect(smtpConfigurationDelete(mockContext, mockUser))
      .rejects.toMatchObject({ extensions: { code: 'FORBIDDEN_ACCESS' } });
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });
});

// ---------- smtpConfigurationTest ----------

describe('smtpConfigurationTest', () => {
  it('should delegate to smtpTest and return true on success', async () => {
    const { smtpTest } = await import('../../../../src/database/smtp');
    vi.mocked(smtpTest).mockResolvedValueOnce(true);
    const result = await smtpConfigurationTest(mockContext, mockUser, 'test@example.com');
    expect(result).toBe(true);
    expect(smtpTest).toHaveBeenCalledWith('test@example.com');
  });

  it('should propagate errors thrown by smtpTest', async () => {
    const { smtpTest } = await import('../../../../src/database/smtp');
    vi.mocked(smtpTest).mockRejectedValueOnce(new Error('connection refused'));
    await expect(smtpConfigurationTest(mockContext, mockUser, 'test@example.com'))
      .rejects.toThrow('connection refused');
  });
});

