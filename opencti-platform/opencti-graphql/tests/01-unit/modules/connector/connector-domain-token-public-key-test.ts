import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntityConnector } from '../../../../src/modules/connector/connector-types';

const {
  mockGetEntitiesMapFromCache,
  mockFindConnectorManagers,
  mockAddUserTokenByAdmin,
  mockRevokeUserTokenByAdmin,
  redisStore,
} = vi.hoisted(() => ({
  mockGetEntitiesMapFromCache: vi.fn(),
  mockFindConnectorManagers: vi.fn(),
  mockAddUserTokenByAdmin: vi.fn(),
  mockRevokeUserTokenByAdmin: vi.fn(),
  redisStore: new Map<string, string>(),
}));

vi.mock('../../../../src/lock/master-lock', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/lock/master-lock')>()),
  lockResources: vi.fn().mockResolvedValue({ unlock: vi.fn() }),
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: mockGetEntitiesMapFromCache,
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  getClientBase: () => ({
    get: async (key: string) => redisStore.get(key) ?? null,
    setex: async (key: string, _expiration: number, value: string) => redisStore.set(key, value),
    expire: async () => 1,
  }),
}));

vi.mock('../../../../src/modules/connector/connector-repository', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-repository')>()),
  findConnectorManagers: mockFindConnectorManagers,
}));

vi.mock('../../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/user/user-domain')>()),
  addUserTokenByAdmin: mockAddUserTokenByAdmin,
  revokeUserTokenByAdmin: mockRevokeUserTokenByAdmin,
}));

vi.mock('../../../../src/modules/catalog/catalog-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/catalog/catalog-domain')>()),
  encryptValue: (publicKey: string, value: string) => `${publicKey}|${value}`,
}));

import { computeManagedConnectorContractConfiguration } from '../../../../src/modules/connector/connector-domain';

const context = {} as AuthContext;
const user = { id: 'admin' } as AuthUser;

// Only the fields read by the tested function
const connector = {
  id: 'connector-a',
  internal_id: 'connector-a',
  name: 'connector-a',
  catalog_id: 'catalog-x',
  connector_user_id: 'user-1',
  connector_type: 'EXTERNAL_IMPORT',
  manager_contract_configuration: [],
} as unknown as BasicStoreEntityConnector;

// Tokens of the user, kept in sync by the add and revoke mocks
let userTokens: { id: string; name: string }[];

const readToken = async () => {
  const configuration = await computeManagedConnectorContractConfiguration(context, user, connector);
  return configuration.find(({ key }) => key === 'OPENCTI_TOKEN')?.value;
};

describe('managed connector token encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    redisStore.clear();
    userTokens = [];
    let tokenCount = 0;
    mockGetEntitiesMapFromCache.mockImplementation(async () => new Map([
      ['user-1', { id: 'user-1', internal_id: 'user-1', api_tokens: userTokens }],
    ]));
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-1' }]);
    mockAddUserTokenByAdmin.mockImplementation(async (_context, _user, _userId, { name }) => {
      tokenCount += 1;
      userTokens.push({ id: `token-${tokenCount}`, name });
      return { plaintext_token: `plaintext-${tokenCount}` };
    });
    mockRevokeUserTokenByAdmin.mockImplementation(async (_context, _user, _userId, tokenId) => {
      userTokens = userTokens.filter(({ id }) => id !== tokenId);
      return tokenId;
    });
  });

  it('should keep serving the cached token while the manager public key does not change', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    expect(await readToken()).toBe('public-key-1|plaintext-1');

    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
  });

  it('should encrypt a new token with the new public key when the manager registers again', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-2' }]);

    expect(await readToken()).toBe('public-key-2|plaintext-2');
    // The token encrypted with the previous key is revoked, the new one is then served from the cache
    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledWith(context, expect.anything(), 'user-1', 'token-1');
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2']);
    expect(await readToken()).toBe('public-key-2|plaintext-2');
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(2);
  });

  it('should fail with a functional error, without touching the token, when no connector manager is registered', async () => {
    await readToken();
    mockFindConnectorManagers.mockResolvedValue([]);

    await expect(readToken()).rejects.toThrow('No connector manager registered');
    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
  });
});
