import { describe, expect, it } from 'vitest';
import { addUser, userDelete, userEditField } from '../../../src/domain/user';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { generateStandardId } from '../../../src/schema/identifier';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { getEntitiesListFromCache, refreshCacheForEntity } from '../../../src/database/cache';
import type { AuthUser } from '../../../src/types/user';
import type { StoreEntity } from '../../../src/types/store';

const USERS_CACHE_LENGTH = 7;

describe('CacheManager refresh and reset test', () => {
  const testUser = {
    password: 'testuserpass',
    user_email: 'test-user-cache@opencti.io',
    name: 'test user cache',
  };
  const testUserId: string = generateStandardId(ENTITY_TYPE_USER, testUser);
  let userInstance: StoreEntity | null = null;
  it('CacheManager should refresh one user after create', async () => {
    const usersCacheInitial = await getEntitiesListFromCache<AuthUser>(testContext, ADMIN_USER, ENTITY_TYPE_USER);
    expect(usersCacheInitial.length).toEqual(USERS_CACHE_LENGTH);
    // create user
    const addedUser = await addUser(testContext, ADMIN_USER, testUser);
    userInstance = addedUser;
    expect(addedUser).toBeDefined();
    expect(addedUser.standard_id).toEqual(testUserId);
    // refresh cache
    await refreshCacheForEntity(addedUser);
    // test cache
    const usersCache = await getEntitiesListFromCache<AuthUser>(testContext, ADMIN_USER, ENTITY_TYPE_USER);
    expect(usersCache.length).toEqual(USERS_CACHE_LENGTH + 1);
    const userInCache = usersCache.find((u) => u.standard_id === testUserId);
    expect(userInCache).toBeDefined();
    expect(userInCache?.user_email).toEqual(testUser.user_email);
  });
  it('CacheManager should refresh one user after update', async () => {
    const userNameEdit = 'test user cache edit';
    const inputs = [{ key: 'name', value: [userNameEdit] }];
    const editedUser = await userEditField(testContext, ADMIN_USER, testUserId, inputs);
    // refresh cache
    await refreshCacheForEntity(editedUser);
    // test cache
    const usersCache = await getEntitiesListFromCache<AuthUser>(testContext, ADMIN_USER, ENTITY_TYPE_USER);
    const userInCache = usersCache.find((u) => u.standard_id === testUserId);
    expect(userInCache).toBeDefined();
    expect(userInCache?.user_email).toEqual(testUser.user_email);
    expect(userInCache?.name).toEqual(userNameEdit);
  });
  it('CacheManager should refresh one user after delete', async () => {
    // delete user
    await userDelete(testContext, ADMIN_USER, testUserId);
    // refresh cache
    await refreshCacheForEntity(userInstance as StoreEntity);
    // test cache
    const usersCache = await getEntitiesListFromCache<AuthUser>(testContext, ADMIN_USER, ENTITY_TYPE_USER);
    expect(usersCache.length).toEqual(USERS_CACHE_LENGTH);
    const userInCache = usersCache.find((u) => u.standard_id === testUserId);
    expect(userInCache).toBeUndefined();
  });
});
