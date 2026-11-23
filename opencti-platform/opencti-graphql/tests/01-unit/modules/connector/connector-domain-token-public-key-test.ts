import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntityConnector } from '../../../../src/modules/connector/connector-types';

const {
  mockGetEntitiesMapFromCache,
  mockStoreLoadById,
  mockFindConnectorManagers,
  mockAddUserTokenByAdmin,
  mockRevokeUserTokenByAdmin,
  redisStore,
  heldLocks,
} = vi.hoisted(() => ({
  mockGetEntitiesMapFromCache: vi.fn(),
  mockStoreLoadById: vi.fn(),
  mockFindConnectorManagers: vi.fn(),
  mockAddUserTokenByAdmin: vi.fn(),
  mockRevokeUserTokenByAdmin: vi.fn(),
  redisStore: new Map<string, string>(),
  heldLocks: new Map<string, Promise<void>>(),
}));

// A lock held per resource, as the real one: concurrent reads on the same resource run one after the other
vi.mock('../../../../src/lock/master-lock', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/lock/master-lock')>()),
  lockResources: async ([resourceId]: string[]) => {
    while (heldLocks.has(resourceId)) {
      await heldLocks.get(resourceId);
    }
    let release = () => {};
    heldLocks.set(resourceId, new Promise((resolve) => {
      release = resolve;
    }));
    return {
      unlock: async () => {
        heldLocks.delete(resourceId);
        release();
      },
    };
  },
}));

vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesMapFromCache: mockGetEntitiesMapFromCache,
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: mockStoreLoadById,
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
// A connector sharing the user, on another catalog
const connectorOtherCatalog = { ...connector, id: 'connector-b', internal_id: 'connector-b', name: 'connector-b', catalog_id: 'catalog-y' } as BasicStoreEntityConnector;
// A connector sharing the user and the catalog
const connectorSameCatalog = { ...connector, id: 'connector-c', internal_id: 'connector-c', name: 'connector-c' } as BasicStoreEntityConnector;

// Tokens of the user as stored, kept in sync by the add and revoke mocks
let userTokens: { id: string; name: string; managed_by_type?: string; managed_by_id?: string }[];
// Tokens of the user as the user cache sees them: the stored ones, unless a test makes the cache lag behind
let cachedUserTokens: { id: string; name: string; managed_by_type?: string; managed_by_id?: string }[] | null;

// Each read is one Composer request, with its own context
const readToken = async (target = connector, context = {} as AuthContext) => {
  const configuration = await computeManagedConnectorContractConfiguration(context, user, target);
  return configuration.find(({ key }) => key === 'OPENCTI_TOKEN')?.value;
};

describe('managed connector token encryption', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    redisStore.clear();
    heldLocks.clear();
    userTokens = [];
    cachedUserTokens = null;
    let tokenCount = 0;
    mockGetEntitiesMapFromCache.mockImplementation(async () => new Map([
      ['user-1', { id: 'user-1', internal_id: 'user-1', api_tokens: cachedUserTokens ?? userTokens }],
    ]));
    mockStoreLoadById.mockImplementation(async (_context, _user, id) => ({ id, internal_id: id, api_tokens: [...userTokens] }));
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-1' }]);
    mockAddUserTokenByAdmin.mockImplementation(async (_context, _user, _userId, { name }, managedBy) => {
      tokenCount += 1;
      userTokens.push({ id: `token-${tokenCount}`, name, managed_by_type: managedBy?.type, managed_by_id: managedBy?.id });
      return { token_id: `token-${tokenCount}`, plaintext_token: `plaintext-${tokenCount}` };
    });
    // As the real one, which reloads the user from the database
    mockRevokeUserTokenByAdmin.mockImplementation(async (_context, _user, _userId, tokenId) => {
      if (!userTokens.some(({ id }) => id === tokenId)) {
        throw new Error('Token not found');
      }
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
    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'user-1', 'token-1');
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2']);
    expect(await readToken()).toBe('public-key-2|plaintext-2');
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(2);
  });

  it('should not serve a revoked token when the manager key comes back to a previous one', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-2' }]);
    expect(await readToken()).toBe('public-key-2|plaintext-2');
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-1' }]);

    // token-1 was revoked by the first rotation: a new token is encrypted with the key back in use
    expect(await readToken()).toBe('public-key-1|plaintext-3');
    expect(userTokens.map(({ id }) => id)).toEqual(['token-3']);
    expect(await readToken()).toBe('public-key-1|plaintext-3');
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(3);
  });

  it('should keep serving the cached token when the user holds several Composer tokens', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    // A stale users cache can leave several tokens tagged with this connector: the first one found is not the cached one
    userTokens.unshift({ id: 'token-other', name: 'Composer managed token (connector: connector-a)', managed_by_type: 'Connector', managed_by_id: 'connector-a' });

    expect(await readToken()).toBe('public-key-1|plaintext-1');
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
  });

  it('should regenerate the token when the cache holds a value written before the record format', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    // Before the fix, the bare encrypted token was cached, whatever the key it was encrypted with
    redisStore.set('composer:connector:connector-a:token:user-1', 'previous-public-key|plaintext-1');

    expect(await readToken()).toBe('public-key-1|plaintext-2');
    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'user-1', 'token-1');
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2']);
  });

  it('should not revoke the token of a connector sharing the user on another catalog', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    // No record yet for the other catalog: a connector created later, or a record expired
    expect(await readToken(connectorOtherCatalog)).toBe('public-key-1|plaintext-2');

    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(userTokens.map(({ id }) => id)).toEqual(['token-1', 'token-2']);
    expect(await readToken()).toBe('public-key-1|plaintext-1');
  });

  it('should regenerate the token when it was revoked while the user holds another Composer token', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    expect(await readToken(connectorOtherCatalog)).toBe('public-key-1|plaintext-2');
    // Revoked by an administrator
    userTokens = userTokens.filter(({ id }) => id !== 'token-1');

    expect(await readToken()).toBe('public-key-1|plaintext-3');
    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2', 'token-3']);
  });

  it('should keep serving the cached token while the user cache lags behind its creation', async () => {
    cachedUserTokens = [];
    expect(await readToken()).toBe('public-key-1|plaintext-1');

    expect(await readToken()).toBe('public-key-1|plaintext-1');
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
  });

  it('should rotate the token once when a connector is read twice at the same time', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-2' }]);

    const tokens = await Promise.all([readToken(), readToken()]);
    expect(tokens).toEqual(['public-key-2|plaintext-2', 'public-key-2|plaintext-2']);
    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledTimes(1);
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2']);
  });

  it('should rotate the own token of each connector sharing the user and the catalog when read at the same time', async () => {
    expect(await readToken()).toBe('public-key-1|plaintext-1');
    expect(await readToken(connectorSameCatalog)).toBe('public-key-1|plaintext-2');
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key-2' }]);

    // Composer resolves all managed connectors in parallel
    const tokens = await Promise.all([readToken(), readToken(connectorSameCatalog)]);
    expect([...tokens].sort()).toEqual(['public-key-2|plaintext-3', 'public-key-2|plaintext-4']);
    expect(mockRevokeUserTokenByAdmin.mock.calls.map(([, , , tokenId]) => tokenId).sort()).toEqual(['token-1', 'token-2']);
    expect(userTokens.map(({ managed_by_id }) => managed_by_id).sort()).toEqual(['connector-a', 'connector-c']);
  });

  it('should load the connector manager once per request', async () => {
    const context = {} as AuthContext;
    await Promise.all([readToken(connector, context), readToken(connectorOtherCatalog, context)]);

    expect(mockFindConnectorManagers).toHaveBeenCalledTimes(1);
  });

  it('should fail with a functional error, without touching the token, when no connector manager is registered', async () => {
    await readToken();
    mockFindConnectorManagers.mockResolvedValue([]);

    await expect(readToken()).rejects.toThrow('No connector manager registered');
    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
  });
});
