import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntityConnector } from '../../../../src/modules/connector/connector-types';

const {
  mockGetEntitiesMapFromCache,
  mockFindConnectorManagers,
  mockAddUserTokenByAdmin,
  mockRevokeUserTokenByAdmin,
  mockInternalDeleteElementById,
  redisStore,
} = vi.hoisted(() => ({
  mockGetEntitiesMapFromCache: vi.fn(),
  mockFindConnectorManagers: vi.fn(),
  mockAddUserTokenByAdmin: vi.fn(),
  mockRevokeUserTokenByAdmin: vi.fn(),
  mockInternalDeleteElementById: vi.fn(),
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
  notify: vi.fn(),
  getClientBase: () => ({
    get: async (key: string) => redisStore.get(key) ?? null,
    setex: async (key: string, _expiration: number, value: string) => redisStore.set(key, value),
    expire: async () => 1,
    del: async (key: string) => redisStore.delete(key),
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

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  internalDeleteElementById: mockInternalDeleteElementById,
}));

vi.mock('../../../../src/domain/work', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/domain/work')>()),
  deleteWorkForConnector: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-rabbitmq', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-rabbitmq')>()),
  unregisterConnector: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-redis')>()),
  redisDeleteConnectorHeartbeat: vi.fn(),
  redisDeleteConnectorErrors: vi.fn(),
}));

vi.mock('../../../../src/listener/UserActionListener', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/listener/UserActionListener')>()),
  publishUserAction: vi.fn(),
}));

import { computeManagedConnectorContractConfiguration, connectorDelete } from '../../../../src/modules/connector/connector-domain';

const context = {} as AuthContext;
const user = { id: 'admin' } as AuthUser;

// Only the fields read by the tested functions
const managedConnector = (id: string, catalogId: string, userId = 'user-1') => ({
  id,
  internal_id: id,
  name: id,
  catalog_id: catalogId,
  connector_user_id: userId,
  connector_type: 'EXTERNAL_IMPORT',
  manager_contract_configuration: [],
}) as unknown as BasicStoreEntityConnector;

// Tokens of the user, kept in sync by the add and revoke mocks
let userTokens: { id: string; name: string }[];

const readToken = async (connectorEntity: BasicStoreEntityConnector) => {
  const configuration = await computeManagedConnectorContractConfiguration(context, user, connectorEntity);
  return configuration.find(({ key }) => key === 'OPENCTI_TOKEN')?.value;
};

describe('managed connector token', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    redisStore.clear();
    userTokens = [];
    let tokenCount = 0;
    mockGetEntitiesMapFromCache.mockImplementation(async () => new Map([
      ['user-1', { id: 'user-1', internal_id: 'user-1', api_tokens: userTokens }],
    ]));
    mockFindConnectorManagers.mockResolvedValue([{ public_key: 'public-key' }]);
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

  it('should give each connector of a user its own token', async () => {
    const connectorA = managedConnector('connector-a', 'catalog-x');
    const connectorB = managedConnector('connector-b', 'catalog-y');

    expect(await readToken(connectorA)).toBe('public-key|plaintext-1');
    expect(await readToken(connectorB)).toBe('public-key|plaintext-2');

    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(userTokens.map(({ name }) => name)).toEqual(['Composer managed token connector-a', 'Composer managed token connector-b']);
    // Connector A keeps receiving its still valid token
    expect(await readToken(connectorA)).toBe('public-key|plaintext-1');
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(2);
  });

  it('should keep serving the cached token when the catalog id changes', async () => {
    expect(await readToken(managedConnector('connector-a', 'catalog-x'))).toBe('public-key|plaintext-1');
    expect(await readToken(managedConnector('connector-a', 'catalog-z'))).toBe('public-key|plaintext-1');

    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
  });

  it('should only revoke the token of the connector when its cache is lost', async () => {
    const connectorA = managedConnector('connector-a', 'catalog-x');
    await readToken(connectorA);
    await readToken(managedConnector('connector-b', 'catalog-y'));
    userTokens.push({ id: 'legacy-token', name: 'Composer managed token' });
    redisStore.clear();

    expect(await readToken(connectorA)).toBe('public-key|plaintext-3');

    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledTimes(1);
    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledWith(context, expect.anything(), 'user-1', 'token-1');
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2', 'legacy-token', 'token-3']);
  });

  it('should fail with a functional error when the connector user does not exist', async () => {
    await expect(readToken(managedConnector('connector-a', 'catalog-x', 'deleted-user')))
      .rejects.toThrow('Managed connector user not found');
    await expect(readToken(managedConnector('connector-a', 'catalog-x', '')))
      .rejects.toThrow('Managed connector user not found');
    expect(mockAddUserTokenByAdmin).not.toHaveBeenCalled();
  });

  it('should fail with a functional error, without revoking the token, when no connector manager is registered', async () => {
    const connectorA = managedConnector('connector-a', 'catalog-x');
    await readToken(connectorA);
    redisStore.clear();
    mockFindConnectorManagers.mockResolvedValue([]);

    await expect(readToken(connectorA)).rejects.toThrow('No connector manager registered');
    expect(mockRevokeUserTokenByAdmin).not.toHaveBeenCalled();
    expect(mockAddUserTokenByAdmin).toHaveBeenCalledTimes(1);
  });

  it('should revoke the token of a deleted managed connector, and only this one', async () => {
    const connectorA = managedConnector('connector-a', 'catalog-x');
    await readToken(connectorA);
    await readToken(managedConnector('connector-b', 'catalog-y'));
    mockInternalDeleteElementById.mockResolvedValueOnce({ element: connectorA });

    expect(await connectorDelete(context, user, 'connector-a')).toBe('connector-a');

    expect(mockRevokeUserTokenByAdmin).toHaveBeenCalledWith(context, expect.anything(), 'user-1', 'token-1');
    expect(userTokens.map(({ id }) => id)).toEqual(['token-2']);
    expect(redisStore.has('composer:connector:connector-a:token:user-1')).toBe(false);
    expect(redisStore.has('composer:connector:connector-b:token:user-1')).toBe(true);
  });

  it('should still delete a managed connector whose token cannot be revoked', async () => {
    const connectorA = managedConnector('connector-a', 'catalog-x');
    await readToken(connectorA);
    mockInternalDeleteElementById.mockResolvedValueOnce({ element: connectorA });
    mockRevokeUserTokenByAdmin.mockRejectedValueOnce(new Error('revoke failure'));

    expect(await connectorDelete(context, user, 'connector-a')).toBe('connector-a');
  });
});
