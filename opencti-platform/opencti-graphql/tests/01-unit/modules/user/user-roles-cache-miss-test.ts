import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const cachedUsers = vi.hoisted(() => ({ map: new Map<string, unknown>() }));
const mockFullRelationsList = vi.hoisted(() => vi.fn());
const mockFullEntitiesList = vi.hoisted(() => vi.fn());

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn(async () => []),
  getEntitiesMapFromCache: vi.fn(async () => cachedUsers.map),
  getEntityFromCache: vi.fn(async () => ({})),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: (...args: unknown[]) => mockFullEntitiesList(...args),
  fullEntitiesThoughAggregationConnection: vi.fn(),
  fullEntitiesThroughRelationsToList: vi.fn(async () => []),
  fullRelationsList: (...args: unknown[]) => mockFullRelationsList(...args),
  internalFindByIds: vi.fn(async () => []),
  internalFindByIdsMapped: vi.fn(async () => ({})),
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  pageRegardingEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  notify: vi.fn(),
  publishCacheResetEvent: vi.fn(),
  setEditContext: vi.fn(),
}));

const USER_ID = 'user-id';
const GROUP_ID = 'group-id';
const roleA = { id: 'role-a', internal_id: 'role-a', name: 'A role' };
const roleB = { id: 'role-b', internal_id: 'role-b', name: 'B role' };

const loadUserRoles = async () => {
  const { userRoles } = await import('../../../../src/modules/user/user-domain');
  return userRoles;
};

describe('User domain - userRoles when the users cache misses the user', () => {
  beforeEach(() => {
    cachedUsers.map = new Map();
    mockFullRelationsList.mockReset();
    mockFullEntitiesList.mockReset();
  });

  it('should return the roles of the cached user', async () => {
    cachedUsers.map = new Map([[USER_ID, { id: USER_ID, roles: [roleB, roleA] }]]);
    const userRoles = await loadUserRoles();
    const roles = await userRoles({} as AuthContext, {} as AuthUser, USER_ID, { orderBy: 'name' } as never);
    expect(roles.map((r) => r.name)).toEqual(['A role', 'B role']);
    expect(mockFullRelationsList).not.toHaveBeenCalled();
  });

  it('should resolve the roles from the database when the user is not in the cache', async () => {
    mockFullRelationsList.mockImplementation(async (_ctx: unknown, _user: unknown, type: string) => (
      type === 'member-of'
        ? [{ fromId: USER_ID, toId: GROUP_ID }]
        : [{ fromId: GROUP_ID, toId: roleA.internal_id }, { fromId: GROUP_ID, toId: roleB.internal_id }]
    ));
    mockFullEntitiesList.mockResolvedValue([roleA, roleB]);
    const userRoles = await loadUserRoles();
    const roles = await userRoles({} as AuthContext, {} as AuthUser, USER_ID, { orderBy: 'name', orderMode: 'desc' } as never);
    expect(roles.map((r) => r.name)).toEqual(['B role', 'A role']);
  });

  it('should return no role, never throw, for a user absent from the cache and without group', async () => {
    mockFullRelationsList.mockResolvedValue([]);
    mockFullEntitiesList.mockResolvedValue([]);
    const userRoles = await loadUserRoles();
    await expect(userRoles({} as AuthContext, {} as AuthUser, USER_ID, {} as never)).resolves.toEqual([]);
  });

  it('should return no role for a cached user without roles', async () => {
    cachedUsers.map = new Map([[USER_ID, { id: USER_ID }]]);
    const userRoles = await loadUserRoles();
    await expect(userRoles({} as AuthContext, {} as AuthUser, USER_ID, {} as never)).resolves.toEqual([]);
  });
});
