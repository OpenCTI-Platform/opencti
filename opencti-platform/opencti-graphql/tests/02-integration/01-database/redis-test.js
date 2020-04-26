import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  clearAccessCache,
  delEditContext,
  fetchEditContext,
  getAccessCache,
  getRedisVersion,
  initRedisClient,
  setEditContext,
  storeAccessCache,
} from '../../../src/database/redis';
import { OPENCTI_ADMIN_UUID } from '../../../src/domain/user';

describe('Redis basic and utils', () => {
  it('should redis in correct version', async () => {
    // Just wait one second to let redis client initialize
    const redisVersion = await initRedisClient().then(() => getRedisVersion());
    expect(redisVersion).toEqual(expect.stringMatching(/^5\./g));
  });
});

describe('Redis context management', () => {
  const contextInstanceId = uuid();
  const user = { id: OPENCTI_ADMIN_UUID, email: 'test@opencti.io' };
  const input = { field: 'test', data: 'random' };

  it('should set context for a user', async () => {
    await initRedisClient();
    const setContext = await setEditContext(user, contextInstanceId, input);
    expect(setContext).toEqual('OK');
    let getContext = await fetchEditContext(contextInstanceId);
    expect(input).toEqual(head(getContext));
    const deletedContext = await delEditContext(user, contextInstanceId);
    expect(deletedContext).toEqual(1);
    getContext = await fetchEditContext(contextInstanceId);
    expect(getContext).toEqual([]);
  });

  it('should use redis as connection cache ', async () => {
    await initRedisClient();
    const tokenUUID = uuid();
    const accessData = { token: OPENCTI_ADMIN_UUID };
    let data = await getAccessCache(tokenUUID);
    expect(data).toBeNull();
    await storeAccessCache(tokenUUID, accessData, 5);
    data = await getAccessCache(tokenUUID);
    expect(data).toEqual(accessData);
    // Wait expiration time
    await (async () => new Promise((resolve) => setTimeout(resolve, 6000)))();
    data = await getAccessCache(tokenUUID);
    expect(data).toBeNull();
    // Manual clean
    await storeAccessCache(tokenUUID, accessData);
    data = await getAccessCache(tokenUUID);
    expect(data).toEqual(accessData);
    await clearAccessCache(tokenUUID);
    data = await getAccessCache(tokenUUID);
    expect(data).toBeNull();
  });
});
