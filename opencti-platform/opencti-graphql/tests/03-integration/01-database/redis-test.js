import { describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  delEditContext,
  deleteAllPlaybookExecutions,
  delUserContext,
  fetchEditContext,
  getLastPlaybookExecutions,
  getRedisVersion,
  lockResource,
  PLAYBOOK_EXECUTIONS_MAX_LENGTH,
  redisClearTelemetry,
  redisGetForgotPasswordOtp,
  redisGetTelemetry,
  redisPlaybookUpdate,
  redisSetForgotPasswordOtp,
  redisSetTelemetryAdd,
  setEditContext,
} from '../../../src/database/redis';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

describe('Redis basic and utils', () => {
  it('should redis in correct version', async () => {
    // Just wait one second to let redis client initialize
    const redisVersion = await getRedisVersion();
    expect(redisVersion).toMatch(/^7|8\./g);
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
    const id = uuid();
    const email = 'user@test.com';
    const firstOtp = 'first-otp';
    const secondOtp = 'second-otp';

    await redisSetForgotPasswordOtp(id, { hashedOtp: firstOtp, email });
    const storedFirst = await redisGetForgotPasswordOtp(id);
    expect(storedFirst.hashedOtp).toBe(firstOtp);

    await redisSetForgotPasswordOtp(id, { hashedOtp: secondOtp, email });
    const storedSecond = await redisGetForgotPasswordOtp(id);
    expect(storedSecond.hashedOtp).toBe(secondOtp);
  });

  it('should expire forgot_password_otp after TTL', async () => {
    const id = uuid();
    const email = 'user@test.com';
    const otp = 'otp-with-ttl';
    const testTTL = 2;

    await redisSetForgotPasswordOtp(id, { hashedOtp: otp, email }, testTTL);
    const stored = await redisGetForgotPasswordOtp(id);
    expect(stored.hashedOtp).toBe(otp);

    await new Promise((resolve) => {
      setTimeout(() => resolve(), (testTTL + 1) * 1000);
    });
    const expired = await redisGetForgotPasswordOtp(id);
    expect(expired.hashedOtp).toBeUndefined();
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

describe('Redis playbook executions tests', () => {
  const PLAYBOOK_ID = 'c8fbdb3a-ec02-404d-8517-af553323ec4e';
  const dummyBundle = { id: 'd61892ff-4d78-4e60-ab7d-4238def85767', spec_version: '2.1', type: 'bundle', objects: [] };
  it('should save playbook executions and get saved keys', async () => {
    const PLAYBOOK_EXECUTION_ID = '5b977923-9005-49f7-8765-6bfed282dd1d';
    const envelop = {
      playbook_execution_id: PLAYBOOK_EXECUTION_ID,
      playbook_id: PLAYBOOK_ID,
      last_execution_step: 'a12f34fa-fc80-4c09-be47-3502bdd071d3',
      ['step_59df0ada-9339-4875-98a1-34a8c090f2ff']: { message: 'Create observables successfully executed in a few seconds',
        status: 'success', in_timestamp: '2026-03-04T17:10:39.099Z', out_timestamp: '2026-03-04T17:10:39.099Z', duration: 0,
        bundle: dummyBundle },
    };
    await redisPlaybookUpdate(envelop);
    const executions = await getLastPlaybookExecutions(PLAYBOOK_ID);
    expect(executions.length).toEqual(1);
    expect(executions[0].id).toEqual(PLAYBOOK_EXECUTION_ID);
    expect(executions[0].playbook_id).toEqual(PLAYBOOK_ID);
  });
  it('should save no more than PLAYBOOK_EXECUTIONS_MAX_LENGTH playbook executions and get saved keys', async () => {
    // try to save more than PLAYBOOK_EXECUTIONS_MAX_LENGTH
    for (let i = 0; i < (PLAYBOOK_EXECUTIONS_MAX_LENGTH + 1); i++) {
      const last_execution_step = uuid();
      const PLAYBOOK_EXECUTION_ID = uuid();
      const envelop = {
        playbook_execution_id: PLAYBOOK_EXECUTION_ID,
        playbook_id: PLAYBOOK_ID,
        last_execution_step: last_execution_step,
        [`step_${last_execution_step}`]: { message: 'dummy step', status: 'success', bundle: dummyBundle,
          in_timestamp: '2026-03-04T17:10:39.099Z', out_timestamp: '2026-03-04T17:10:39.099Z', duration: 0 },
      };
      await redisPlaybookUpdate(envelop);
    }
    const executions = await getLastPlaybookExecutions(PLAYBOOK_ID);
    expect(executions.length).toEqual(PLAYBOOK_EXECUTIONS_MAX_LENGTH);
  });
  it('should delete playbook executions', async () => {
    await deleteAllPlaybookExecutions(PLAYBOOK_ID);
    const executions = await getLastPlaybookExecutions(PLAYBOOK_ID);
    expect(executions.length).toEqual(0);
  });
});
