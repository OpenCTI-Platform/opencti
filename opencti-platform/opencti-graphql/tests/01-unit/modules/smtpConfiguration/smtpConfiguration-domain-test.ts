import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as InternalObject from '../../../../src/domain/internalObject';
import * as Middleware from '../../../../src/database/middleware';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import {
  getSmtpConfiguration,
  getSmtpConfigurationById,
  smtpConfigurationAdd,
  smtpConfigurationDelete,
  smtpConfigurationTest,
  smtpConfigurationUpdate,
} from '../../../../src/modules/smtpConfiguration/smtpConfiguration-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
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

// ---------- getSmtpConfigurationById ----------

describe('getSmtpConfigurationById', () => {
  it('should return the configuration for a known id', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(MOCK_CONFIG);
    const result = await getSmtpConfigurationById(mockContext, mockUser, MOCK_CONFIG.id);
    expect(result).toEqual(MOCK_CONFIG);
    expect(MiddlewareLoader.storeLoadById).toHaveBeenCalledWith(mockContext, mockUser, MOCK_CONFIG.id, 'SmtpConfiguration');
  });

  it('should return null for an unknown id', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(null as any);
    const result = await getSmtpConfigurationById(mockContext, mockUser, 'unknown-id');
    expect(result).toBeNull();
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

  it('should pass input as-is to publishUserAction (secrets sanitized in Chunk 2)', async () => {
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
  it('should throw UnsupportedError (stub)', async () => {
    await expect(smtpConfigurationTest(mockContext, mockUser, 'test@example.com'))
      .rejects.toThrow('smtpConfigurationTest is not yet implemented');
  });
});
