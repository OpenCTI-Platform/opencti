import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock Redis before importing the module under test
const mockPipeline = {
  hgetall: vi.fn(),
  exec: vi.fn(),
};

const mockClient = {
  zrangebyscore: vi.fn(),
  zremrangebyscore: vi.fn(),
  pipeline: vi.fn(() => mockPipeline),
};

vi.mock('../../../src/database/redis', () => ({
  getClientBase: vi.fn(() => mockClient),
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  },
}));

import { getConsumersForCollection, type RedisConsumerData } from '../../../src/graphql/streamConsumerRegistry';

describe('getConsumersForCollection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockClient.zremrangebyscore.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return an empty array when no connection IDs exist in the sorted set', async () => {
    mockClient.zrangebyscore.mockResolvedValue([]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toEqual([]);
    expect(mockClient.zrangebyscore).toHaveBeenCalledOnce();
    // Pipeline should not be created when there are no connections
    expect(mockClient.pipeline).not.toHaveBeenCalled();
  });

  it('should return consumer data for a single valid consumer', async () => {
    const connectionId = 'conn-abc-123';
    mockClient.zrangebyscore.mockResolvedValue([connectionId]);

    const consumerHash: Record<string, string> = {
      connectionId,
      collectionId: 'collection-1',
      userId: 'user-1',
      userEmail: 'user1@test.com',
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: 'event-42',
      deliveryRate: '12.5',
      processingRate: '25.0',
      resolutionRate: '3.14',
      lastUpdate: '1741257600000',
    };

    mockPipeline.exec.mockResolvedValue([[null, consumerHash]]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toHaveLength(1);
    expect(result[0]).toEqual<RedisConsumerData>({
      connectionId,
      collectionId: 'collection-1',
      userId: 'user-1',
      userEmail: 'user1@test.com',
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: 'event-42',
      deliveryRate: 12.5,
      processingRate: 25.0,
      resolutionRate: 3.14,
      lastUpdate: 1741257600000,
    });
  });

  it('should return multiple consumers for a collection', async () => {
    const connectionIds = ['conn-1', 'conn-2', 'conn-3'];
    mockClient.zrangebyscore.mockResolvedValue(connectionIds);

    const makeConsumerHash = (id: string, userId: string): Record<string, string> => ({
      connectionId: id,
      collectionId: 'collection-multi',
      userId,
      userEmail: `${userId}@test.com`,
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: 'event-1',
      deliveryRate: '1.0',
      processingRate: '2.0',
      resolutionRate: '0.5',
      lastUpdate: '1741257600000',
    });

    mockPipeline.exec.mockResolvedValue([
      [null, makeConsumerHash('conn-1', 'user-a')],
      [null, makeConsumerHash('conn-2', 'user-b')],
      [null, makeConsumerHash('conn-3', 'user-c')],
    ]);

    const result = await getConsumersForCollection('collection-multi');

    expect(result).toHaveLength(3);
    expect(result.map((r) => r.userId)).toEqual(['user-a', 'user-b', 'user-c']);
    expect(result.map((r) => r.connectionId)).toEqual(['conn-1', 'conn-2', 'conn-3']);
    // Verify pipeline was called for each connection
    expect(mockPipeline.hgetall).toHaveBeenCalledTimes(3);
  });

  it('should skip consumers with pipeline errors', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-ok', 'conn-err']);

    const validHash: Record<string, string> = {
      connectionId: 'conn-ok',
      collectionId: 'collection-1',
      userId: 'user-1',
      userEmail: 'user1@test.com',
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: 'event-1',
      deliveryRate: '5',
      processingRate: '10',
      resolutionRate: '1',
      lastUpdate: '1741257600000',
    };

    mockPipeline.exec.mockResolvedValue([
      [null, validHash],
      [new Error('Redis error'), null],
    ]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toHaveLength(1);
    expect(result[0].connectionId).toBe('conn-ok');
  });

  it('should skip consumers with empty hash data (deleted key)', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1', 'conn-empty']);

    const validHash: Record<string, string> = {
      connectionId: 'conn-1',
      collectionId: 'collection-1',
      userId: 'user-1',
      userEmail: 'user1@test.com',
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: '',
      deliveryRate: '0',
      processingRate: '0',
      resolutionRate: '0',
      lastUpdate: '1741257600000',
    };

    mockPipeline.exec.mockResolvedValue([
      [null, validHash],
      [null, {}], // Empty hash (key was deleted / expired)
    ]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toHaveLength(1);
    expect(result[0].connectionId).toBe('conn-1');
  });

  it('should skip consumers missing userId (incomplete data)', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1']);

    const incompleteHash: Record<string, string> = {
      connectionId: 'conn-1',
      collectionId: 'collection-1',
      // userId is missing
      userEmail: 'user@test.com',
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: '',
      deliveryRate: '0',
      processingRate: '0',
      resolutionRate: '0',
      lastUpdate: '1741257600000',
    };

    mockPipeline.exec.mockResolvedValue([[null, incompleteHash]]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toHaveLength(0);
  });

  it('should skip consumers missing connectedAt (incomplete data)', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1']);

    const incompleteHash: Record<string, string> = {
      connectionId: 'conn-1',
      collectionId: 'collection-1',
      userId: 'user-1',
      userEmail: 'user@test.com',
      // connectedAt is missing
      lastEventId: '',
      deliveryRate: '0',
      processingRate: '0',
      resolutionRate: '0',
      lastUpdate: '1741257600000',
    };

    mockPipeline.exec.mockResolvedValue([[null, incompleteHash]]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toHaveLength(0);
  });

  it('should use fallback values when optional fields are missing from the hash', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1']);

    // Minimal valid hash: only userId and connectedAt are required
    const minimalHash: Record<string, string> = {
      userId: 'user-1',
      connectedAt: '2026-03-06T10:00:00.000Z',
    };

    mockPipeline.exec.mockResolvedValue([[null, minimalHash]]);

    const result = await getConsumersForCollection('my-collection');

    expect(result).toHaveLength(1);
    expect(result[0]).toEqual<RedisConsumerData>({
      connectionId: 'conn-1', // Falls back to connectionIds[i]
      collectionId: 'my-collection', // Falls back to collectionId argument
      userId: 'user-1',
      userEmail: '', // Defaults to empty string
      connectedAt: '2026-03-06T10:00:00.000Z',
      lastEventId: '', // Defaults to empty string
      deliveryRate: 0, // parseFloat('0') = 0
      processingRate: 0,
      resolutionRate: 0,
      lastUpdate: 0, // parseInt('0', 10) = 0
    });
  });

  it('should return empty array when pipeline result is null', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1']);
    mockPipeline.exec.mockResolvedValue(null);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toEqual([]);
  });

  it('should clean up stale entries from the sorted set', async () => {
    mockClient.zrangebyscore.mockResolvedValue([]);

    await getConsumersForCollection('collection-cleanup');

    // zrangebyscore should be called with staleCutoff and +inf
    expect(mockClient.zrangebyscore).toHaveBeenCalledWith(
      '{stream_consumers}:collection-cleanup',
      expect.any(Number),
      '+inf',
    );
  });

  it('should correctly parse numeric fields from string values', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1']);

    const hash: Record<string, string> = {
      connectionId: 'conn-1',
      collectionId: 'collection-1',
      userId: 'user-1',
      userEmail: 'admin@example.com',
      connectedAt: '2026-01-15T08:30:00.000Z',
      lastEventId: 'event-99',
      deliveryRate: '123.456',
      processingRate: '789.012',
      resolutionRate: '0.001',
      lastUpdate: '1736930000000',
    };

    mockPipeline.exec.mockResolvedValue([[null, hash]]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toHaveLength(1);
    expect(result[0].deliveryRate).toBe(123.456);
    expect(result[0].processingRate).toBe(789.012);
    expect(result[0].resolutionRate).toBe(0.001);
    expect(result[0].lastUpdate).toBe(1736930000000);
  });

  it('should skip entries where data is null (not an error but null data)', async () => {
    mockClient.zrangebyscore.mockResolvedValue(['conn-1']);

    mockPipeline.exec.mockResolvedValue([[null, null]]);

    const result = await getConsumersForCollection('collection-1');

    expect(result).toEqual([]);
  });

  it('should query Redis sorted set with correct key prefix', async () => {
    mockClient.zrangebyscore.mockResolvedValue([]);

    await getConsumersForCollection('test-collection-id');

    expect(mockClient.zrangebyscore).toHaveBeenCalledWith(
      '{stream_consumers}:test-collection-id',
      expect.any(Number),
      '+inf',
    );
  });
});
