import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  delEditContext,
  fetchEditContext,
  getRedisVersion,
  initRedisClient,
  setEditContext,
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
});
