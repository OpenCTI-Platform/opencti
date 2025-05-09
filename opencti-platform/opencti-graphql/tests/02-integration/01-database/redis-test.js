import { describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  delEditContext,
  delUserContext,
  fetchEditContext,
  getRedisVersion,
  lockResource,
  redisClearTelemetry,
  redisGetForgotPasswordOtp,
  redisGetTelemetry,
  redisSetForgotPasswordOtp,
  redisSetTelemetryAdd,
  setEditContext
} from '../../../src/database/redis';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

describe('Redis basic and utils', () => {
  it('should redis in correct version', async () => {
    // Just wait one second to let redis client initialize
    const redisVersion = await getRedisVersion();
    expect(redisVersion).toEqual(expect.stringMatching(/^7\./g));
  });

  it('should redis telemetry add, get and clean work', async () => {
    await redisClearTelemetry();
    expect(await redisGetTelemetry('notExistingGaugeInRedis'), 'Calling telemetry data before redis has numbers should not crash').toBe(0);

    await redisSetTelemetryAdd('fakeGaugeforUnitTest', 3);
    expect(await redisGetTelemetry('fakeGaugeforUnitTest')).toBe(3);

    await redisSetTelemetryAdd('fakeGaugeforUnitTest', 2);
    expect(await redisGetTelemetry('fakeGaugeforUnitTest')).toBe(5);

    await redisClearTelemetry();
    expect(await redisGetTelemetry('fakeGaugeforUnitTest')).toBe(0);
  });

  it('should store and overwrite forgot_password_otp)', async () => {
    const email = 'user@test.com';
    const firstOtp = 'first-otp';
    const secondOtp = 'second-otp';

    await redisSetForgotPasswordOtp(email, firstOtp);
    const storedFirst = await redisGetForgotPasswordOtp(email);
    expect(storedFirst.otp).toBe(firstOtp);

    await redisSetForgotPasswordOtp(email, secondOtp);
    const storedSecond = await redisGetForgotPasswordOtp(email);
    expect(storedSecond.otp).toBe(secondOtp);
  });

  it('should expire forgot_password_otp after TTL', async () => {
    const email = 'user@test.com';
    const otp = 'otp-with-ttl';
    const testTTL = 2;

    await redisSetForgotPasswordOtp(email, otp, testTTL);
    const stored = await redisGetForgotPasswordOtp(email);
    expect(stored.otp).toBe(otp);

    await new Promise((resolve) => {
      setTimeout(() => resolve(), (testTTL + 1) * 1000);
    });
    const expired = await redisGetForgotPasswordOtp(email);
    expect(expired.otp).toBeNull();
  });
});

describe('Redis should lock', () => {
  it('should redis lock mono', async () => {
    const lock = await lockResource(['id1', 'id2']);
    const lock2Promise = lockResource(['id3', 'id2']);
    setTimeout(() => lock.unlock(), 3000);
    const lock2 = await lock2Promise;
    await lock2.unlock();
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
