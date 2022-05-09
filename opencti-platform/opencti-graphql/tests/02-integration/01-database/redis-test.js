import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  delEditContext,
  delUserContext,
  fetchEditContext,
  getRedisVersion,
  lockResource,
  setEditContext,
} from '../../../src/database/redis';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

describe('Redis basic and utils', () => {
  it('should redis in correct version', async () => {
    // Just wait one second to let redis client initialize
    const redisVersion = await getRedisVersion();
    expect(redisVersion).toEqual(expect.stringMatching(/^7\./g));
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
    expect(input.data).toEqual(head(getContext).data);
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
    expect(input.data).toEqual(head(getContext).data);
    getContext = await fetchEditContext(secondContextId);
    expect(input.data).toEqual(head(getContext).data);
    await delUserContext(user);
    getContext = await fetchEditContext(contextInstanceId);
    expect(getContext).toEqual([]);
    getContext = await fetchEditContext(secondContextId);
    expect(getContext).toEqual([]);
  });
});
