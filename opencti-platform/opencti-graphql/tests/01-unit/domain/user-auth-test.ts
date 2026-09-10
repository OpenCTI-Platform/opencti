import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../src/database/cache';
import { authenticateUserByToken } from '../../../src/domain/user';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { SYSTEM_USER } from '../../../src/utils/access';
import { generateTokenHmac } from '../../../src/modules/user/user-domain';

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

describe('User Domain - Authentication', async () => {
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
    capabilities: [{ name: 'APIACCESS_USETOKEN' }],
  };

  const newTokenValue = 'flgrn_octi_tkn_secureRandomString';
  const newTokenHash = await generateTokenHmac(newTokenValue);

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
    capabilities: [{ name: 'APIACCESS_USETOKEN' }],
  };

  const expiredTokenValue = 'flgrn_octi_tkn_expired';
  const expiredTokenHash = await generateTokenHmac(expiredTokenValue);
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
    capabilities: [{ name: 'APIACCESS_USETOKEN' }],
  };

  beforeEach(() => {
    vi.resetAllMocks();

    // Default mock implementation for cache
    const usersList = [legacyUser, modernUser, expiredUser];

    vi.spyOn(Cache, 'getEntitiesListFromCache').mockImplementation(async (_ctx, _user, type) => {
      if (type === ENTITY_TYPE_USER) {
        return usersList as any;
      }
      return [];
    });
    vi.spyOn(Cache, 'getEntityFromCache').mockImplementation(async (_ctx, _user, type) => {
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

  // Story 2.3 Verification
  it('should reject token at exact expiration time (Boundary)', async () => {
    // Current time equals expires_at
    const boundaryTokenValue = 'flgrn_octi_tkn_boundary';
    const boundaryHash = await generateTokenHmac(boundaryTokenValue);
    const boundaryUser = {
      ...modernUser, id: 'boundary-user', api_tokens: [{
        id: 'boundary',
        hash: boundaryHash,
        expires_at: new Date().toISOString(), // Expires NOW
      }],
    };

    // Mock update
    const usersList = [boundaryUser];
    vi.spyOn(Cache, 'getEntitiesListFromCache').mockResolvedValue(usersList as any);

    await expect(authenticateUserByToken(context, mockReq, boundaryTokenValue))
      .rejects.toThrowError('Token expired');
  });

  it('should reject revoked token (valid hash but removed from profile)', async () => {
    const revokedTokenValue = 'flgrn_octi_tkn_revoked';

    // If the token was revoked (removed from the list), the user simply won't be found by hash anymore.
    const userWithRevoked = { ...modernUser, api_tokens: [] }; // Token removed from list
    const usersList = [userWithRevoked];
    vi.spyOn(Cache, 'getEntitiesListFromCache').mockResolvedValue(usersList as any);

    // Since no user has this hash in api_tokens, authentication fails with the generic "not found" error.
    await expect(authenticateUserByToken(context, mockReq, revokedTokenValue))
      .rejects.toThrowError('Cannot identify user with token');
  });

  it('should reject authentication if user lacks SETTINGS_SETACCESSTOKEN capability', async () => {
    const noCapUser = {
      ...modernUser,
      id: 'no-cap-user',
      capabilities: [{ name: 'SOME_OTHER_CAP' }],
    };
    const validTokenValue = 'flgrn_octi_tkn_nocap';
    const validHash = await generateTokenHmac(validTokenValue);

    noCapUser.api_tokens = [{ id: 't1', hash: validHash, name: 'T1', created_at: new Date().toISOString() }];

    const usersList = [noCapUser];
    vi.spyOn(Cache, 'getEntitiesListFromCache').mockResolvedValue(usersList as any);

    await expect(authenticateUserByToken(context, mockReq, validTokenValue))
      .rejects.toThrowError('You are not allowed to use API Access Tokens');
  });
});
