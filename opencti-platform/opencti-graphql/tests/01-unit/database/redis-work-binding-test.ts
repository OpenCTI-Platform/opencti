import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// A fake redis client: every command of the transaction is recorded, nothing is connected.
const { mockTx, mockClient } = vi.hoisted(() => {
  const tx = { hset: vi.fn(), hincrby: vi.fn(), exec: vi.fn() };
  const client = { on: vi.fn(), multi: vi.fn(() => tx), disconnect: vi.fn() };
  return { mockTx: tx, mockClient: client };
});

vi.mock('ioredis', () => ({
  Redis: vi.fn(function RedisMock() {
    return mockClient;
  }),
  Cluster: vi.fn(function ClusterMock() {
    return mockClient;
  }),
}));
vi.mock('graphql-redis-subscriptions', () => ({
  RedisPubSub: vi.fn(function RedisPubSubMock() {
    return {};
  }),
}));
vi.mock('../../../src/config/credentials', () => ({
  enrichWithRemoteCredentials: vi.fn(async (_service: string, auth: unknown) => auth),
}));
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  const overrides: Record<string, unknown> = { 'redis:mode': 'single', 'redis:ca': [], 'redis:hostname': 'redis.example.test', 'redis:port': 6379, 'redis:database': 0 };
  return {
    ...actual,
    default: { ...actual.default, get: (key: string) => (key in overrides ? overrides[key] : actual.default.get(key)) },
  };
});

import { initializeRedisClients, redisInitializeWork } from '../../../src/database/redis';

// hset is called with (id, [field, value, field, value, ...])
const storedFields = () => {
  const [, flatPairs] = mockTx.hset.mock.calls[0];
  const fields: Record<string, unknown> = {};
  for (let i = 0; i < flatPairs.length; i += 2) fields[flatPairs[i]] = flatPairs[i + 1];
  return fields;
};

describe('redisInitializeWork', () => {
  beforeAll(async () => {
    await initializeRedisClients();
  });

  beforeEach(() => {
    mockTx.hset.mockReset();
    mockTx.exec.mockReset();
  });

  it('should not bind a work that does not come from a form submission', async () => {
    await redisInitializeWork('work-1', false);
    expect(mockTx.hset).toHaveBeenCalledOnce();
    expect(mockTx.hset.mock.calls[0][0]).toBe('work-1');
    expect(storedFields()).toEqual({ is_initialized: true, is_multipart: false });
    expect(mockTx.exec).toHaveBeenCalledOnce();
  });

  it('should bind the work to the applicant, the form and the draft of a form submission', async () => {
    await redisInitializeWork('work-1', false, { applicant_id: 'user-1', form_id: 'form-1', draft_id: 'draft-1' });
    expect(storedFields()).toEqual({
      is_initialized: true,
      is_multipart: false,
      form_applicant_id: 'user-1',
      form_id: 'form-1',
      form_draft_id: 'draft-1',
    });
  });

  it('should store an empty draft id for a submission that created no draft', async () => {
    await redisInitializeWork('work-1', false, { applicant_id: 'user-1', form_id: 'form-1', draft_id: null });
    expect(storedFields()).toMatchObject({ form_applicant_id: 'user-1', form_id: 'form-1', form_draft_id: '' });
    mockTx.hset.mockReset();
    await redisInitializeWork('work-1', true, { applicant_id: 'user-1', form_id: 'form-1' });
    expect(storedFields()).toMatchObject({ is_multipart: true, form_draft_id: '' });
  });
});
