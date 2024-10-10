import { expect, it, describe } from 'vitest';
import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import { delEditContext, fetchEditContext, getRedisVersion, lockResource, setEditContext } from '../../../src/database/redis';
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
    await setEditContext(user, contextInstanceId, input);
    const initialContext = await fetchEditContext(contextInstanceId);
    expect(input.data).toEqual(head(initialContext).data);
    await delEditContext(user, contextInstanceId);
    const getContext = await fetchEditContext(contextInstanceId);
    expect(getContext).toEqual([]);
  });
});
