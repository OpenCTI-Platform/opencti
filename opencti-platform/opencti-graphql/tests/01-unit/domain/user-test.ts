import { describe, expect, it, vi, beforeEach } from 'vitest';
import { DateTime } from 'luxon';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';
import { updateAttribute } from '../../../src/database/middleware';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { TokenDuration, type UserTokenAddInput } from '../../../src/generated/graphql';
import { authenticateUserByJWT, authenticateUserByToken, authenticateUserByUserId, checkPasswordInlinePolicy, isSensitiveChangesAllowed } from '../../../src/domain/user';
import { addUserToken, generateSecureToken } from '../../../src/modules/user/user-domain';
import { testContext } from '../../utils/testQuery';
import { isUserHasCapability } from '../../../src/utils/access';
import { getEntitiesMapFromCache, getEntityFromCache } from '../../../src/database/cache';
import { verifyXtmJwt, isOwnIssuer } from '../../../src/domain/xtm-auth';
import { elLoadBy } from '../../../src/database/engine';
import { generateTokenHmac } from '../../../src/modules/user/user-domain';
import { updateTokenUsage } from '../../../src/database/redis/token_usage';

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn().mockResolvedValue({ element: { id: 'mock-id', user_email: 'test@test.com' } }),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntitiesMapFromCache: vi.fn().mockResolvedValue(new Map()),
  getEntityFromCache: vi.fn().mockResolvedValue(null),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(),
}));

vi.mock('../../../src/utils/access', async () => {
  const actual = await vi.importActual('../../../src/utils/access');
  return {
    ...actual,
    isUserHasCapability: vi.fn().mockReturnValue(true),
  };
});

vi.mock('../../../src/domain/xtm-auth', () => ({
  verifyXtmJwt: vi.fn(),
  isOwnIssuer: vi.fn(),
}));

vi.mock('../../../src/database/engine', () => ({
  elLoadBy: vi.fn(),
  elRawDeleteByQuery: vi.fn(),
}));

vi.mock('../../../src/database/redis/token_usage', () => ({
  getTokensUsage: vi.fn().mockResolvedValue([]),
  updateTokenUsage: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../src/modules/user/user-domain', async () => {
  const actual = await vi.importActual('../../../src/modules/user/user-domain');
  return {
    ...actual,
    generateTokenHmac: vi.fn(),
    addUserTokenByAdmin: vi.fn(),
  };
});

describe('password checker', () => {
  it('should no policy applied', async () => {
    const policy = {};
    expect(checkPasswordInlinePolicy(testContext, policy, '').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, policy, 'a').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, policy, '!').length).toBe(0);
  });
  it('should password_policy_min_length policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_length: 4 }, '123').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_length: 4 }, '1234').length).toBe(0);
  });
  it('should password_policy_max_length policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 0 }, '123').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 2 }, '123').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 4 }, '1234').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_max_length: 4 }, '12345').length).toBe(1);
  });
  it('should password_policy_min_symbols policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_symbols: 4 }, '123é').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_symbols: 4 }, '1!2!3$4$').length).toBe(0);
  });
  it('should password_policy_min_numbers policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_numbers: 1 }, 'aaa').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_numbers: 4 }, 'a1a2a3a4').length).toBe(0);
  });
  it('should password_policy_min_words policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello-world').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello|world').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello_world').length).toBe(0);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_words: 2 }, 'hello world').length).toBe(0);
  });
  it('should password_policy_min_lowercase policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_lowercase: 4 }, 'AAAA').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_lowercase: 4 }, 'aaaa').length).toBe(0);
  });
  it('should password_policy_min_uppercase policy applied', async () => {
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_uppercase: 4 }, 'aXaaXa').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, { password_policy_min_uppercase: 4 }, 'AxAxAxA)').length).toBe(0);
  });
  it('should complex policy applied', async () => {
    const policy01 = {
      password_policy_min_length: 10,
      password_policy_min_symbols: 2,
      password_policy_min_numbers: 3,
      password_policy_min_words: 3,
      password_policy_min_lowercase: 2,
      password_policy_min_uppercase: 2,
    };
    expect(checkPasswordInlinePolicy(testContext, policy01, 'aXa77&&2aXa').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, policy01, 'ab-CD-&^123').length).toBe(0);
    const policy02 = {
      password_policy_min_length: 4,
      password_policy_min_symbols: 1,
      password_policy_min_numbers: 2,
      password_policy_min_words: 0,
      password_policy_min_lowercase: 0,
      password_policy_min_uppercase: 0,
    };
    expect(checkPasswordInlinePolicy(testContext, policy02, 'test!').length).toBe(1);
    const policy03 = {
      password_policy_min_length: 2,
      password_policy_max_length: 5,
      password_policy_min_symbols: 1,
      password_policy_min_numbers: 0,
      password_policy_min_words: 0,
      password_policy_min_lowercase: 2,
      password_policy_min_uppercase: 1,
    };
    expect(checkPasswordInlinePolicy(testContext, policy03, 'julA').length).toBe(1);
    expect(checkPasswordInlinePolicy(testContext, policy03, 'ju!lA').length).toBe(0);
  });
});

describe('isSensitiveChangesAllowed use case coverage', () => {
  const NOT_INFRA_ADMIN_USER_ID = '1c0925fe-ab65-42a1-8e96-ee6dc7fab4fa';

  it('should user with one role and not can_manage_sensitive_config set be not allowed to change sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role without can_manage_sensitive_config field should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should user with one role can_manage_sensitive_config=true be allow change sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: true,
    },
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with can_manage_sensitive_config field true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with one role can_manage_sensitive_config=false not be allow change sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false,
    },
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with can_manage_sensitive_config field false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should user with 2 roles one without can_manage_sensitive_config, the other is false', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false,
    },
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with one can_manage_sensitive_config undefined and one false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should user with 2 roles one without can_manage_sensitive_config, the other is true', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: true,
    },
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with one can_manage_sensitive_config true should be isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should user with 2 roles all with can_manage_sensitive_config set to false', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false,
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false,
    },
    ];

    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'Role with all can_manage_sensitive_config field false should be isSensitiveChangesAllowed=false').toBeFalsy();
  });

  it('should INFRA admin bypass sensitive conf', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false,
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: false,
    },
    ];

    const result = isSensitiveChangesAllowed(OPENCTI_ADMIN_UUID, roles);
    expect(result, 'OPENCTI_ADMIN_UUID should be always isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should INFRA user with 2 roles one without can_manage_sensitive_config, the other is true', async () => {
    // subset of role data
    const roles = [{
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
    },
    {
      _index: 'opencti_internal_objects-000001',
      base_type: 'ENTITY',
      confidence: 100,
      created_at: '2024-08-06T13:30:04.478Z',
      description: 'Administrator role that bypass every capabilities',
      entity_type: 'Role',
      id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      internal_id: '57312f0e-f276-44f8-97d3-88191ee57e1a',
      name: 'Administrator',
      updated_at: '2024-08-06T13:30:04.478Z',
      can_manage_sensitive_config: true,
    },
    ];

    const result = isSensitiveChangesAllowed(OPENCTI_ADMIN_UUID, roles);
    expect(result, 'OPENCTI_ADMIN_UUID should be always isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should INFRA admin bypass sensitive conf with zero role', async () => {
    // subset of role data
    const roles: any[] = [];
    const result = isSensitiveChangesAllowed(OPENCTI_ADMIN_UUID, roles);
    expect(result, 'OPENCTI_ADMIN_UUID should be always isSensitiveChangesAllowed=true').toBeTruthy();
  });

  it('should a user with zero role be isSensitiveChangesAllowed=false', async () => {
    // subset of role data
    const roles: any[] = [];
    const result = isSensitiveChangesAllowed(NOT_INFRA_ADMIN_USER_ID, roles);
    expect(result, 'A user with no role should be isSensitiveChangesAllowed=false').toBeFalsy();
  });
});

describe('API Token Generation', () => {
  it('generateSecureToken should produce valid token and hash', async () => {
    const { token, hash } = await generateSecureToken();
    expect(token).toBeDefined();
    expect(hash).toBeDefined();
    expect(token.startsWith('flgrn_octi_tkn_')).toBe(true);
    expect(token.length).toBeGreaterThan(64); // Prefix + 64 random chars (approx)
    expect(hash.length).toBe(44);
  });

  it('addUserToken should create token, patch user, log action, and return plaintext', async () => {
    const user = { id: 'user-123', user_email: 'test@example.com' } as AuthUser;
    const input = { duration: 'UNLIMITED', name: 'Test Token' } as UserTokenAddInput;
    const context = { user: { id: 'admin' } } as AuthContext;

    const result = await addUserToken(context, user, input);

    expect(result.plaintext_token).toBeDefined();
    expect(result.plaintext_token.startsWith('flgrn_octi_tkn_')).toBe(true);
    expect(result.expires_at).toBeNull(); // Unlimited duration

    // Verify DB Patch
    expect(updateAttribute).toHaveBeenCalledWith(
      context,
      user,
      user.id,
      ENTITY_TYPE_USER,
      expect.arrayContaining([
        expect.objectContaining({
          key: 'api_tokens',
          value: expect.arrayContaining([
            expect.objectContaining({
              name: 'Test Token',
              // Hash validation would be ideal but hash is generated inside
            }),
          ]),
          operation: 'add',
        }),
      ]),
    );
  });

  it('addUserToken should calculate expiration correctly', async () => {
    const user = { id: 'user-123' } as AuthUser;
    const input = { duration: TokenDuration.Days_30, name: 'Expiring Token' } as UserTokenAddInput;
    const context = {} as AuthContext;

    const result = await addUserToken(context, user, input);

    expect(result.expires_at).toBeDefined();
    const expires = DateTime.fromISO(result.expires_at as string);
    const now = DateTime.now();
    const diff = expires.diff(now, 'days').days;
    // expect(diff).toBeCloseTo(30, 0); // 30.0 days
    expect(Math.abs(diff - 30)).toBeLessThan(0.1);
  });
});

// --- Helper for building a minimal mock request ---
const buildMockReq = (overrides: Record<string, any> = {}) => ({
  ip: '127.0.0.1',
  headers: {},
  header: () => undefined,
  socket: { remoteAddress: '127.0.0.1' },
  ...overrides,
});

// --- Helper for a minimal valid cached user ---
const buildCachedUser = (id: string, extra: Record<string, any> = {}) => ({
  id,
  account_status: 'Active',
  groups: [],
  organizations: [],
  headers_audit: [],
  ...extra,
});

// --- Minimal settings object required by validateUser / internalAuthenticateUser ---
const MOCK_SETTINGS = { platform_organization: null };

// --- Tests for authentication methods ---

describe('authenticateUserByUserId', () => {
  const mockContext = testContext;
  const mockReq = buildMockReq();

  it('should return the authenticated user when found in cache', async () => {
    const cachedUser = buildCachedUser('user-abc');
    const usersMap = new Map([['user-abc', cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);
    vi.mocked(getEntityFromCache).mockResolvedValue(MOCK_SETTINGS as any);

    const result = await authenticateUserByUserId(mockContext, mockReq, 'user-abc');

    expect(result).toBeDefined();
    expect(result.id).toBe('user-abc');
    expect(result.origin).toBeDefined();
  });

  it('should throw FunctionalError when user id is not found in cache', async () => {
    const usersMap = new Map();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);

    await expect(
      authenticateUserByUserId(mockContext, mockReq, 'unknown-user'),
    ).rejects.toThrow('Cannot identify user with id');
  });
});

describe('authenticateUserByJWT', () => {
  const mockContext = testContext;
  const mockReq = buildMockReq();

  beforeEach(() => {
    vi.mocked(verifyXtmJwt).mockReset();
    vi.mocked(isOwnIssuer).mockReset();
    vi.mocked(elLoadBy).mockReset();
  });

  it('should authenticate by userId when issuer is own platform', async () => {
    vi.mocked(verifyXtmJwt).mockResolvedValue({
      payload: { iss: 'https://opencti.example.com', sub: 'user-jwt-1', email: 'u@test.com' },
    } as any);
    vi.mocked(isOwnIssuer).mockReturnValue(true);

    const cachedUser = buildCachedUser('user-jwt-1');
    const usersMap = new Map([['user-jwt-1', cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);
    vi.mocked(getEntityFromCache).mockResolvedValue(MOCK_SETTINGS as any);

    const result = await authenticateUserByJWT(mockContext, mockReq, 'eyFakeToken');

    expect(verifyXtmJwt).toHaveBeenCalledWith('eyFakeToken');
    expect(isOwnIssuer).toHaveBeenCalledWith('https://opencti.example.com');
    expect(result.id).toBe('user-jwt-1');
  });

  it('should throw AuthenticationFailure when own issuer JWT has no sub claim', async () => {
    vi.mocked(verifyXtmJwt).mockResolvedValue({
      payload: { iss: 'https://opencti.example.com', sub: undefined, email: 'u@test.com' },
    } as any);
    vi.mocked(isOwnIssuer).mockReturnValue(true);

    await expect(
      authenticateUserByJWT(mockContext, mockReq, 'eyFakeToken'),
    ).rejects.toThrow('JWT missing sub claim');
  });

  it('should authenticate by email when issuer is external trusted issuer', async () => {
    vi.mocked(verifyXtmJwt).mockResolvedValue({
      payload: { iss: 'https://xtm.example.com', sub: 'ext-user', email: 'trusted@test.com' },
    } as any);
    vi.mocked(isOwnIssuer).mockReturnValue(false);

    // getUserByEmail -> elLoadBy returns a user
    vi.mocked(elLoadBy).mockResolvedValue({ id: 'email-user-1', user_email: 'trusted@test.com' } as any);

    // Cache has this user
    const cachedUser = buildCachedUser('email-user-1');
    const usersMap = new Map([['email-user-1', cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);
    vi.mocked(getEntityFromCache).mockResolvedValue(MOCK_SETTINGS as any);

    const result = await authenticateUserByJWT(mockContext, mockReq, 'eyExternalToken');

    expect(result.id).toBe('email-user-1');
  });

  it('should throw when external trusted issuer JWT has no email claim', async () => {
    vi.mocked(verifyXtmJwt).mockResolvedValue({
      payload: { iss: 'https://xtm.example.com', sub: 'ext-user', email: undefined },
    } as any);
    vi.mocked(isOwnIssuer).mockReturnValue(false);

    await expect(
      authenticateUserByJWT(mockContext, mockReq, 'eyNoEmailToken'),
    ).rejects.toThrow('Trusted issuer JWT missing email claim');
  });

  it('should throw when email from external JWT does not match any user', async () => {
    vi.mocked(verifyXtmJwt).mockResolvedValue({
      payload: { iss: 'https://xtm.example.com', sub: 'ext-user', email: 'unknown@test.com' },
    } as any);
    vi.mocked(isOwnIssuer).mockReturnValue(false);

    // getUserByEmail -> elLoadBy returns null (no match)
    vi.mocked(elLoadBy).mockResolvedValue(null as any);

    await expect(
      authenticateUserByJWT(mockContext, mockReq, 'eyUnknownEmail'),
    ).rejects.toThrow('JWT email does not match any user');
  });

  it('should throw when email user is found in DB but not in cache', async () => {
    vi.mocked(verifyXtmJwt).mockResolvedValue({
      payload: { iss: 'https://xtm.example.com', sub: 'ext-user', email: 'nocache@test.com' },
    } as any);
    vi.mocked(isOwnIssuer).mockReturnValue(false);

    vi.mocked(elLoadBy).mockResolvedValue({ id: 'nocache-user', user_email: 'nocache@test.com' } as any);

    // Cache does NOT have this user
    const usersMap = new Map();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);

    await expect(
      authenticateUserByJWT(mockContext, mockReq, 'eyNoCacheToken'),
    ).rejects.toThrow('Cannot identify user with email');
  });
});

describe('authenticateUserByToken', () => {
  const mockContext = testContext;
  const mockReq = buildMockReq();

  beforeEach(() => {
    vi.mocked(generateTokenHmac).mockReset();
    vi.mocked(isUserHasCapability).mockReturnValue(true);
    vi.mocked(updateTokenUsage).mockResolvedValue(undefined as any);
  });

  it('should authenticate user with a valid non-expired token', async () => {
    const hashedToken = 'hashed-abc-123';
    vi.mocked(generateTokenHmac).mockResolvedValue(hashedToken);

    const futureDate = DateTime.now().plus({ days: 30 }).toISO();
    const cachedUser = buildCachedUser('token-user-1', {
      api_tokens: [{ hash: hashedToken, name: 'My Token', expires_at: futureDate }],
    });
    const usersMap = new Map([[hashedToken, cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);
    vi.mocked(getEntityFromCache).mockResolvedValue(MOCK_SETTINGS as any);

    const result = await authenticateUserByToken(mockContext, mockReq, 'plaintext-token');

    expect(generateTokenHmac).toHaveBeenCalledWith('plaintext-token');
    expect(updateTokenUsage).toHaveBeenCalled();
    expect(result.id).toBe('token-user-1');
  });

  it('should authenticate user with an UNLIMITED (no expiration) token', async () => {
    const hashedToken = 'hashed-unlimited';
    vi.mocked(generateTokenHmac).mockResolvedValue(hashedToken);

    const cachedUser = buildCachedUser('unlimited-user', {
      api_tokens: [{ hash: hashedToken, name: 'Unlimited Token', expires_at: null }],
    });
    const usersMap = new Map([[hashedToken, cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);
    vi.mocked(getEntityFromCache).mockResolvedValue(MOCK_SETTINGS as any);

    const result = await authenticateUserByToken(mockContext, mockReq, 'unlimited-plaintext');

    expect(result.id).toBe('unlimited-user');
  });

  it('should throw FunctionalError when token is expired', async () => {
    const hashedToken = 'hashed-expired';
    vi.mocked(generateTokenHmac).mockResolvedValue(hashedToken);

    const pastDate = DateTime.now().minus({ days: 1 }).toISO();
    const cachedUser = buildCachedUser('expired-user', {
      api_tokens: [{ hash: hashedToken, name: 'Expired Token', expires_at: pastDate }],
    });
    const usersMap = new Map([[hashedToken, cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);

    await expect(
      authenticateUserByToken(mockContext, mockReq, 'expired-plaintext'),
    ).rejects.toThrow('Token expired');
  });

  it('should throw FunctionalError when no user matches the hashed token', async () => {
    vi.mocked(generateTokenHmac).mockResolvedValue('hashed-unknown');

    const usersMap = new Map();
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);

    await expect(
      authenticateUserByToken(mockContext, mockReq, 'no-match-token'),
    ).rejects.toThrow('Cannot identify user with token');
  });

  it('should throw ForbiddenAccess when user lacks APIACCESS_USETOKEN capability', async () => {
    const hashedToken = 'hashed-no-cap';
    vi.mocked(generateTokenHmac).mockResolvedValue(hashedToken);
    vi.mocked(isUserHasCapability).mockReturnValue(false);

    const cachedUser = buildCachedUser('nocap-user', {
      api_tokens: [{ hash: hashedToken, name: 'Token', expires_at: null }],
    });
    const usersMap = new Map([[hashedToken, cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);

    await expect(
      authenticateUserByToken(mockContext, mockReq, 'nocap-plaintext'),
    ).rejects.toThrow('You are not allowed to use API Access Tokens');
  });

  it('should throw FunctionalError when user has no api_tokens array and hash not comparable', async () => {
    const hashedToken = 'hashed-no-tokens';
    vi.mocked(generateTokenHmac).mockResolvedValue(hashedToken);

    const cachedUser = buildCachedUser('notokens-user', {
      api_tokens: [],
    });
    const usersMap = new Map([[hashedToken, cachedUser]]);
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(usersMap as any);

    await expect(
      authenticateUserByToken(mockContext, mockReq, 'notokens-plaintext'),
    ).rejects.toThrow('Cannot identify user with not comparable token');
  });
});
