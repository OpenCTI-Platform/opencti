import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  clearUserAccessCache,
  delEditContext,
  delUserContext,
  fetchEditContext,
  getAccessCache,
  getRedisVersion,
  lockResource,
  setEditContext,
  storeUserAccessCache,
} from '../../../src/database/redis';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

describe('Redis basic and utils', () => {
  it('should redis in correct version', async () => {
    // Just wait one second to let redis client initialize
    const redisVersion = await getRedisVersion();
    expect(redisVersion).toEqual(expect.stringMatching(/^6\./g));
  });
});

describe('Redis should lock', () => {
  it('should redis lock mono', async () => {
    const lock = await lockResource(['id1', 'id2']);
    const lock2Promise = lockResource(['id3', 'id2']);
    setTimeout(() => lock.unlock(), 3000);
    await lock2Promise;
  });
});

describe('Redis context management', () => {
  const contextInstanceId = uuid();
  const user = { id: OPENCTI_ADMIN_UUID, email: 'test@opencti.io' };
  const input = { field: 'test', data: 'random' };

  it('should set context for a user', async () => {
    const setContext = await setEditContext(user, contextInstanceId, input);
    expect(setContext).toEqual('OK');
    let getContext = await fetchEditContext(contextInstanceId);
    expect(input).toEqual(head(getContext));
    const deletedContext = await delEditContext(user, contextInstanceId);
    expect(deletedContext).toEqual(1);
    getContext = await fetchEditContext(contextInstanceId);
    expect(getContext).toEqual([]);
  });

  it('should clear context user', async () => {
    const secondContextId = uuid();
    await setEditContext(user, contextInstanceId, input);
    await setEditContext(user, secondContextId, input);
    let getContext = await fetchEditContext(contextInstanceId);
    expect(input).toEqual(head(getContext));
    getContext = await fetchEditContext(secondContextId);
    expect(input).toEqual(head(getContext));
    await delUserContext(user);
    getContext = await fetchEditContext(contextInstanceId);
    expect(getContext).toEqual([]);
    getContext = await fetchEditContext(secondContextId);
    expect(getContext).toEqual([]);
  });

  it('should use redis as connection cache ', async () => {
    const tokenUUID = uuid();
    const accessData = { token: OPENCTI_ADMIN_UUID };
    let data = await getAccessCache(tokenUUID);
    expect(data).toBeNull();
    await storeUserAccessCache(tokenUUID, accessData, 5);
    data = await getAccessCache(tokenUUID);
    expect(data).toEqual(accessData);
    // Wait expiration time
    await (async () => new Promise((resolve) => setTimeout(resolve, 6000)))();
    data = await getAccessCache(tokenUUID);
    expect(data).toBeNull();
    // Manual clean
    await storeUserAccessCache(tokenUUID, accessData);
    data = await getAccessCache(tokenUUID);
    expect(data).toEqual(accessData);
    await clearUserAccessCache(tokenUUID);
    data = await getAccessCache(tokenUUID);
    expect(data).toBeNull();
  });
});
