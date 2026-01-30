import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../src/database/cache';
import { authenticateUserByToken } from '../../../src/domain/user';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../src/utils/access';
import { hashSHA256 } from '../../../src/utils/hash';

// Mock dependencies
vi.mock('../../../src/database/cache');
vi.mock('../../../src/database/redis'); // to prevent connection attempts
vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...actual,
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() }, // mock logger
  };
});

describe('User Domain - Authentication', () => {
  const context = { user: SYSTEM_USER, req: {} };
  const mockReq = {
    headers: {},
    header: (_: string) => undefined,
    connection: { remoteAddress: '127.0.0.1' },
    socket: { remoteAddress: '127.0.0.1' },
    ip: '127.0.0.1',
  };

  const legacyUser = {
    id: 'user-legacy-id',
    api_token: 'legacy-token-uuid',
    api_tokens: [],
    name: 'Legacy User',
    user_email: 'legacy@test.com',
    account_status: 'Active',
    organizations: [],
    user_service_account: false,
    account_lock_after_date: null,
  };

  const newTokenValue = 'flgrn_octi_tkn_secureRandomString';
  const newTokenHash = hashSHA256(newTokenValue);

  const modernUser = {
    id: 'user-modern-id',
    api_token: 'some-uuid',
    api_tokens: [
      {
        id: 'token-id-1',
        name: 'My Token',
        hash: newTokenHash,
        created_at: new Date().toISOString(),
      },
    ],
    name: 'Modern User',
    user_email: 'modern@test.com',
    account_status: 'Active',
    organizations: [],
    user_service_account: false,
    account_lock_after_date: null,
  };

  const expiredTokenValue = 'flgrn_octi_tkn_expired';
  const expiredTokenHash = hashSHA256(expiredTokenValue);
  const expiredUser = {
    id: 'user-expired-id',
    api_token: 'uuid',
    api_tokens: [
      {
        id: 'token-id-expired',
        name: 'Expired Token',
        hash: expiredTokenHash,
        expires_at: new Date(Date.now() - 10000).toISOString(), // expired
      },
    ],
    account_status: 'Active',
    organizations: [],
    user_service_account: false,
    account_lock_after_date: null,
  };

  beforeEach(() => {
    vi.resetAllMocks();

    // Default mock implementation for cache
    const usersMap = new Map();
    usersMap.set('legacy-token-uuid', legacyUser); // Indexed by api_token (legacy behavior in buildStoreEntityMap)
    usersMap.set(legacyUser.id, legacyUser);
    usersMap.set(modernUser.id, modernUser);
    usersMap.set(expiredUser.id, expiredUser);

    // New: Hash indexing simulation (Story 2.2)
    usersMap.set(newTokenHash, modernUser);
    usersMap.set(expiredTokenHash, expiredUser);

    // For hashed tokens, they are NOT in the map keys (usually, unless we index them? current implementation iterates values)

    vi.spyOn(Cache, 'getEntitiesMapFromCache').mockImplementation(async (ctx, user, type) => {
      if (type === ENTITY_TYPE_USER) {
        return usersMap;
      }
      return new Map();
    });

    vi.spyOn(Cache, 'getEntityFromCache').mockImplementation(async (ctx, user, type) => {
      if (type === ENTITY_TYPE_SETTINGS) {
        return {
          id: 'settings',
          standard_id: 'settings',
          entity_type: ENTITY_TYPE_SETTINGS,
          platform_session_idle_timeout: 0,
          platform_organization: null, // Ensure this is null or valid
        };
      }
      return null as any;
    });
  });

  it('should authenticate with legacy token', async () => {
    const user = await authenticateUserByToken(context, mockReq, 'legacy-token-uuid');
    expect(user).toBeDefined();
    expect(user.id).toBe(legacyUser.id);
  });

  it('should authenticate with new hashed token', async () => {
    const user = await authenticateUserByToken(context, mockReq, newTokenValue);
    expect(user).toBeDefined();
    expect(user.id).toBe(modernUser.id);
  });

  it('should reject expired hashed token', async () => {
    await expect(authenticateUserByToken(context, mockReq, expiredTokenValue))
      .rejects.toThrowError('Token expired');
  });

  it('should reject invalid hashed token', async () => {
    await expect(authenticateUserByToken(context, mockReq, 'flgrn_octi_tkn_invalid'))
      .rejects.toThrowError('Cannot identify user with token');
  });

  it('should reject invalid legacy token', async () => {
    await expect(authenticateUserByToken(context, mockReq, 'invalid-uuid'))
      .rejects.toThrowError('Cannot identify user with token');
  });
});
