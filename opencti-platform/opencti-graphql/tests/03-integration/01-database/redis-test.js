import { describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import { head } from 'ramda';
import {
  delEditContext,
  deleteAllPlaybookExecutions,
  delUserContext,
  fetchEditContext,
  getClientBase,
  getLastPlaybookExecutions,
  getRedisVersion,
  lockResource,
  PLAYBOOK_EXECUTIONS_MAX_LENGTH,
  CACHE_RESET_TOPIC,
  publishCacheResetEvent,
  pubSubSubscription,
  redisAddIngestionHistory,
  redisClearTelemetry,
  redisGetForgotPasswordOtp,
  redisGetIngestionHistory,
  redisGetTelemetry,
  redisGetXtmAgentResponse,
  redisInit,
  redisPlaybookUpdate,
  redisSetForgotPasswordOtp,
  redisSetTelemetryAdd,
  redisSetXtmAgentResponse,
  setEditContext,
} from '../../../src/database/redis';
import { OPENCTI_ADMIN_UUID } from '../../../src/schema/general';

const ingestionHistoryKey = (feedId) => `ingestion-${feedId}-history`;

describe('Redis basic and utils', () => {
  it('should redis in correct version', async () => {
    // Just wait one second to let redis client initialize
    const redisVersion = await getRedisVersion();
    expect(redisVersion).toMatch(/^7|8\./g);
  });

  it('should initializeRedisClients initializes without error', async () => {
    await expect(redisInit()).resolves.not.toThrow();
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

describe('Redis XTM agent response cache', () => {
  it('should return null when no cached response exists', async () => {
    const cached = await redisGetXtmAgentResponse(`missing-key-${uuid()}`);
    expect(cached).toBeNull();
  });

  it('should store and read back a cached agent response with timestamp', async () => {
    const cacheKey = `agent-cache-${uuid()}`;
    await redisSetXtmAgentResponse(cacheKey, '<p>Agent summary</p>', 60);
    const cached = await redisGetXtmAgentResponse(cacheKey);
    expect(cached).not.toBeNull();
    expect(cached.content).toEqual('<p>Agent summary</p>');
    expect(cached.cached_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('should expire a cached agent response after the TTL elapses', async () => {
    const cacheKey = `agent-cache-ttl-${uuid()}`;
    const ttlSeconds = 1;
    await redisSetXtmAgentResponse(cacheKey, 'short-lived', ttlSeconds);
    const initial = await redisGetXtmAgentResponse(cacheKey);
    expect(initial?.content).toEqual('short-lived');

    // Wait ttl + 1s to absorb Redis scheduling jitter under CI load.
    await new Promise((resolve) => {
      setTimeout(() => resolve(), (ttlSeconds + 1) * 1000);
    });

    const expired = await redisGetXtmAgentResponse(cacheKey);
    expect(expired).toBeNull();
  });

  it('should be a no-op when ttl is zero or negative', async () => {
    const cacheKey = `agent-cache-disabled-${uuid()}`;
    await redisSetXtmAgentResponse(cacheKey, 'should-not-be-stored', 0);
    expect(await redisGetXtmAgentResponse(cacheKey)).toBeNull();

    await redisSetXtmAgentResponse(cacheKey, 'should-not-be-stored', -10);
    expect(await redisGetXtmAgentResponse(cacheKey)).toBeNull();
  });

  it('should return null and not throw when the cached payload is not valid JSON', async () => {
    const cacheKey = `agent-cache-corrupt-${uuid()}`;
    await getClientBase().set(`xtm_agent_cache:${cacheKey}`, 'this is not json', 'EX', 60);
    const cached = await redisGetXtmAgentResponse(cacheKey);
    expect(cached).toBeNull();
  });

  it('should return null when the cached payload is valid JSON but the wrong shape', async () => {
    // Cover the cases a defensive shape check should reject: bare scalars,
    // arrays, objects missing `content`, and objects whose `content` /
    // `cached_at` are not strings. Any of these slipping through would
    // make the consumer emit an SSE `done` event with `content:
    // undefined`, which is exactly what the validation prevents.
    const corruptPayloads = [
      JSON.stringify('a bare string'),
      JSON.stringify(42),
      JSON.stringify(null),
      JSON.stringify(['arr']),
      JSON.stringify({ cached_at: '2026-05-28T00:00:00.000Z' }), // missing content
      JSON.stringify({ content: 'x' }), // missing cached_at
      JSON.stringify({ content: 123, cached_at: '2026-05-28T00:00:00.000Z' }), // non-string content
      JSON.stringify({ content: 'x', cached_at: 123 }), // non-string cached_at
    ];
    for (const payload of corruptPayloads) {
      const cacheKey = `agent-cache-shape-${uuid()}`;
      await getClientBase().set(`xtm_agent_cache:${cacheKey}`, payload, 'EX', 60);
      const cached = await redisGetXtmAgentResponse(cacheKey);
      expect(cached, `payload ${payload} should be rejected`).toBeNull();
    }
  });
});

describe('Redis ingestion history', () => {
  it('should add and read ingestion history', async () => {
    const feedId = `feed-${uuid()}`;
    const log = { timestamp: new Date().toISOString(), status: 'success', messages: ['first-log'] };

    await getClientBase().del(ingestionHistoryKey(feedId));
    await redisAddIngestionHistory(feedId, log);
    const history = await redisGetIngestionHistory(feedId);

    expect(history).toHaveLength(1);
    expect(history[0].status).toBe('success');
    expect(history[0].messages).toEqual(['first-log']);
  });

  it('should deduplicate consecutive identical logs and increment count', async () => {
    const feedId = `feed-${uuid()}`;
    const firstTimestamp = '2026-07-06T10:00:00.000Z';
    const secondTimestamp = '2026-07-06T10:01:00.000Z';

    await getClientBase().del(ingestionHistoryKey(feedId));
    await redisAddIngestionHistory(feedId, {
      timestamp: firstTimestamp,
      status: 'error',
      messages: ['same-error'],
    });
    await redisAddIngestionHistory(feedId, {
      timestamp: secondTimestamp,
      status: 'error',
      messages: ['same-error'],
    });

    const history = await redisGetIngestionHistory(feedId);
    expect(history).toHaveLength(1);
    expect(history[0].count).toBe(2);
    expect(history[0].timestamp).toBe(secondTimestamp);
  });

  it('should push a new entry when status or message changes', async () => {
    const feedId = `feed-${uuid()}`;

    await getClientBase().del(ingestionHistoryKey(feedId));
    await redisAddIngestionHistory(feedId, {
      timestamp: '2026-07-06T10:00:00.000Z',
      status: 'success',
      messages: ['ok'],
    });
    await redisAddIngestionHistory(feedId, {
      timestamp: '2026-07-06T10:01:00.000Z',
      status: 'error',
      messages: ['ko'],
    });

    const history = await redisGetIngestionHistory(feedId);
    expect(history).toHaveLength(2);
    expect(history[0].status).toBe('error');
    expect(history[1].status).toBe('success');
  });

  it('should keep only the latest 20 ingestion history entries', async () => {
    const feedId = `feed-${uuid()}`;

    await getClientBase().del(ingestionHistoryKey(feedId));
    for (let i = 0; i < 25; i += 1) {
      await redisAddIngestionHistory(feedId, {
        timestamp: `2026-07-06T10:${String(i).padStart(2, '0')}:00.000Z`,
        status: 'success',
        messages: [`msg-${i}`],
      });
    }

    const history = await redisGetIngestionHistory(feedId);
    expect(history).toHaveLength(20);
    expect(history[0].messages).toEqual(['msg-24']);
    expect(history[19].messages).toEqual(['msg-5']);
  });
});

describe('Redis publishCacheResetEvent', () => {
  it('should publish a cache reset event that subscribers receive', async () => {
    const receivedEvents = [];
    const subscription = await pubSubSubscription(CACHE_RESET_TOPIC, (event) => {
      receivedEvents.push(event);
    });

    try {
      await publishCacheResetEvent('User');

      const timeout = 5000;
      const start = Date.now();
      while (!receivedEvents.some((e) => e.entityType === 'User') && Date.now() - start < timeout) {
        await new Promise((resolve) => { setTimeout(resolve, 10); });
      }

      expect(receivedEvents.length).toBeGreaterThanOrEqual(1);
      const userEvent = receivedEvents.find((e) => e.entityType === 'User');
      expect(userEvent).toBeDefined();
      expect(userEvent.entityType).toBe('User');
    } finally {
      subscription.unsubscribe();
    }
  });

  it('should publish distinct events for different entity types', async () => {
    const receivedEvents = [];
    const subscription = await pubSubSubscription(CACHE_RESET_TOPIC, (event) => {
      receivedEvents.push(event);
    });

    try {
      await publishCacheResetEvent('User');
      await publishCacheResetEvent('Settings');

      const timeout = 5000;
      const start = Date.now();
      while (
        (!receivedEvents.some((e) => e.entityType === 'User') || !receivedEvents.some((e) => e.entityType === 'Settings'))
        && Date.now() - start < timeout
      ) {
        await new Promise((resolve) => { setTimeout(resolve, 10); });
      }

      expect(receivedEvents.length).toBeGreaterThanOrEqual(2);
      expect(receivedEvents.some((e) => e.entityType === 'User')).toBe(true);
      expect(receivedEvents.some((e) => e.entityType === 'Settings')).toBe(true);
    } finally {
      subscription.unsubscribe();
    }
  });
});
