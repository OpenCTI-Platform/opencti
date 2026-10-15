import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockRedisSet = vi.fn();
const mockRedisMget = vi.fn();

vi.mock('../../../../src/database/redis', () => ({
  getClientBase: () => ({ set: mockRedisSet, mget: mockRedisMget }),
}));

import { redisGetRuntimeData, redisSetRuntimeData } from '../../../../src/modules/ingestionHealth/ingestionHealthMonitoring-redis';

const HEARTBEAT = '2026-10-13T12:00:00.000Z';

describe('redisSetRuntimeData', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should store the value under a key per ingestion and type, with the type TTL', async () => {
    await redisSetRuntimeData('connector-1', 'heartbeat', HEARTBEAT);

    expect(mockRedisSet).toHaveBeenCalledWith('ingestion_health:{connector-1}:heartbeat', JSON.stringify(HEARTBEAT), 'EX', 300);
  });

  it('should refuse a value that is not in the format of its type', async () => {
    await expect(redisSetRuntimeData('connector-1', 'heartbeat', 'yesterday')).rejects.toThrow();

    expect(mockRedisSet).not.toHaveBeenCalled();
  });
});

describe('redisGetRuntimeData', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should read every type of one ingestion in one call', async () => {
    mockRedisMget.mockResolvedValueOnce([JSON.stringify(HEARTBEAT)]);

    const result = await redisGetRuntimeData('connector-1');

    expect(mockRedisMget).toHaveBeenCalledWith(['ingestion_health:{connector-1}:heartbeat']);
    expect(result).toEqual({ heartbeat: HEARTBEAT });
  });

  it('should omit absent data', async () => {
    mockRedisMget.mockResolvedValueOnce([null]);

    expect(await redisGetRuntimeData('connector-1')).toEqual({});
  });

  it('should ignore data that is not in the expected format', async () => {
    mockRedisMget.mockResolvedValueOnce([JSON.stringify('yesterday')]);
    expect(await redisGetRuntimeData('connector-1')).toEqual({});

    mockRedisMget.mockResolvedValueOnce(['{invalid']);
    expect(await redisGetRuntimeData('connector-1')).toEqual({});
  });
});
