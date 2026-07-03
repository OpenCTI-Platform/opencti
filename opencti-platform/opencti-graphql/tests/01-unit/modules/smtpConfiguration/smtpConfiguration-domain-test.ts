import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as InternalObject from '../../../../src/domain/internalObject';
import * as Middleware from '../../../../src/database/middleware';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import {
  getSmtpConfiguration,
  smtpConfigurationAdd,
  smtpConfigurationDelete,
  smtpConfigurationTest,
  smtpConfigurationUpdate,
} from '../../../../src/modules/smtpConfiguration/smtpConfiguration-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/database/smtp', () => ({
  smtpTest: vi.fn(async () => true),
}));

vi.mock('../../../../src/modules/smtpConfiguration/smtpConfiguration-crypto', () => ({
  encryptSmtpSecret: vi.fn(async (v: string | null | undefined) => (v ? `encrypted:${v}` : v)),
}));

vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/domain/internalObject', () => ({
  createInternalObject: vi.fn(),
  deleteInternalObject: vi.fn(),
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
      SmtpConfiguration: {
        ADDED_TOPIC: 'SMTP_ADDED',
        EDIT_TOPIC: 'SMTP_EDIT',
        DELETE_TOPIC: 'SMTP_DELETE',
      },
    },
  };
});

const mockContext = { source: 'testing' } as any;
const mockUser = SYSTEM_USER;

const MOCK_CONFIG = {
  id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  entity_type: 'SmtpConfiguration',
  smtp_enabled: false,
  use_db_config: false,
  hostname: 'smtp.example.com',
  port: 587,
} as any;

beforeEach(() => {
  vi.clearAllMocks();
});

// ---------- getSmtpConfiguration ----------

describe('getSmtpConfiguration', () => {
  it('should return null when no configuration exists', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    const result = await getSmtpConfiguration(mockContext, mockUser);
    expect(result).toBeNull();
  });

  it('should return the configuration when exactly one exists', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([MOCK_CONFIG]);
    const result = await getSmtpConfiguration(mockContext, mockUser);
    expect(result).toEqual(MOCK_CONFIG);
  });

  it('should throw a FunctionalError when multiple configurations exist', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([MOCK_CONFIG, { ...MOCK_CONFIG, id: 'bbbb' }]);
    await expect(getSmtpConfiguration(mockContext, mockUser))
      .rejects.toThrow('Multiple SMTP configurations found in database');
  });
});

// ---------- smtpConfigurationAdd ----------

describe('smtpConfigurationAdd', () => {
  it('should create a configuration when none exists', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    vi.mocked(InternalObject.createInternalObject).mockResolvedValue(MOCK_CONFIG);
    const result = await smtpConfigurationAdd(mockContext, mockUser, { smtp_enabled: false, use_db_config: false });
    expect(result).toEqual(MOCK_CONFIG);
    expect(InternalObject.createInternalObject).toHaveBeenCalledOnce();
  });

  it('should throw when a configuration already exists', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([MOCK_CONFIG]);
    await expect(smtpConfigurationAdd(mockContext, mockUser, { smtp_enabled: false, use_db_config: false }))
      .rejects.toThrow('An SMTP configuration already exists');
    expect(InternalObject.createInternalObject).not.toHaveBeenCalled();
  });

  it('should reject port 25', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    await expect(smtpConfigurationAdd(mockContext, mockUser, { port: 25 }))
      .rejects.toThrow('Port 25 is not allowed for SMTP configuration');
    expect(InternalObject.createInternalObject).not.toHaveBeenCalled();
  });

  it('should reject basic auth without username or password', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    await expect(smtpConfigurationAdd(mockContext, mockUser, { auth_type: 'basic' as any }))
      .rejects.toThrow('username and password are required for basic authentication');
    expect(InternalObject.createInternalObject).not.toHaveBeenCalled();
  });

  it('should reject oauth2 without required fields', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    await expect(smtpConfigurationAdd(mockContext, mockUser, { auth_type: 'oauth2' as any, oauth_client_id: 'id' }))
      .rejects.toThrow('oauth_client_id, oauth_client_secret and oauth_issuer are required for OAuth2 authentication');
    expect(InternalObject.createInternalObject).not.toHaveBeenCalled();
  });

  it('should encrypt secrets and never store them in plaintext', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    vi.mocked(InternalObject.createInternalObject).mockResolvedValue(MOCK_CONFIG);
    await smtpConfigurationAdd(mockContext, mockUser, {
      smtp_enabled: true,
      use_db_config: true,
      auth_type: 'basic' as any,
      username: 'user',
      password: 'secret-password',
    });
    const storedInput = (vi.mocked(InternalObject.createInternalObject).mock.calls[0] as any[])[2];
    expect(storedInput).not.toHaveProperty('password');
    expect(storedInput).toHaveProperty('password_encrypted');
    expect(typeof storedInput.password_encrypted).toBe('string');
  });

  it('should drop oauth_access_token from stored input', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    vi.mocked(InternalObject.createInternalObject).mockResolvedValue(MOCK_CONFIG);
    await smtpConfigurationAdd(mockContext, mockUser, {
      smtp_enabled: true,
      use_db_config: true,
      oauth_access_token: 'ephemeral-token',
    });
    const storedInput = (vi.mocked(InternalObject.createInternalObject).mock.calls[0] as any[])[2];
    expect(storedInput).not.toHaveProperty('oauth_access_token');
  });
});

// ---------- smtpConfigurationUpdate ----------

describe('smtpConfigurationUpdate', () => {
  it('should update the configuration and return the updated element', async () => {
    const updated = { ...MOCK_CONFIG, hostname: 'updated.example.com' };
    vi.mocked(Middleware.patchAttribute).mockResolvedValue({ element: updated } as any);
    const result = await smtpConfigurationUpdate(mockContext, mockUser, MOCK_CONFIG.id, { smtp_enabled: true, use_db_config: false, hostname: 'updated.example.com' });
    expect(result).toEqual(updated);
    expect(Middleware.patchAttribute).toHaveBeenCalledWith(mockContext, mockUser, MOCK_CONFIG.id, 'SmtpConfiguration', expect.anything());
  });

  it('should throw FunctionalError when port is 25', async () => {
    await expect(smtpConfigurationUpdate(mockContext, mockUser, MOCK_CONFIG.id, { port: 25 }))
      .rejects.toThrow('Port 25 is not allowed');
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('should reject basic auth without username or password', async () => {
    await expect(smtpConfigurationUpdate(mockContext, mockUser, MOCK_CONFIG.id, { auth_type: 'basic' as any, username: 'user' }))
      .rejects.toThrow('username and password are required for basic authentication');
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('should reject oauth2 without required fields', async () => {
    await expect(smtpConfigurationUpdate(mockContext, mockUser, MOCK_CONFIG.id, { auth_type: 'oauth2' as any }))
      .rejects.toThrow('oauth_client_id, oauth_client_secret and oauth_issuer are required for OAuth2 authentication');
    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
  });

  it('should encrypt secrets before calling patchAttribute', async () => {
    vi.mocked(Middleware.patchAttribute).mockResolvedValue({ element: MOCK_CONFIG } as any);
    await smtpConfigurationUpdate(mockContext, mockUser, MOCK_CONFIG.id, {
      hostname: 'smtp.example.com',
      password: 'new-secret',
    });
    const patchInput = (vi.mocked(Middleware.patchAttribute).mock.calls[0] as any[])[4];
    expect(patchInput).not.toHaveProperty('password');
    expect(patchInput).toHaveProperty('password_encrypted');
    expect(typeof patchInput.password_encrypted).toBe('string');
  });

  it('should not include secrets in publishUserAction audit log', async () => {
    const { publishUserAction } = await import('../../../../src/listener/UserActionListener');
    vi.mocked(Middleware.patchAttribute).mockResolvedValue({ element: MOCK_CONFIG } as any);
    await smtpConfigurationUpdate(mockContext, mockUser, MOCK_CONFIG.id, {
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
  it('should call deleteInternalObject and return the id', async () => {
    vi.mocked(InternalObject.deleteInternalObject).mockResolvedValue(MOCK_CONFIG.id);
    const result = await smtpConfigurationDelete(mockContext, mockUser, MOCK_CONFIG.id);
    expect(result).toBe(MOCK_CONFIG.id);
    expect(InternalObject.deleteInternalObject).toHaveBeenCalledWith(mockContext, mockUser, MOCK_CONFIG.id, 'SmtpConfiguration');
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
