import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockZadd = vi.fn();
const mockZmscore = vi.fn();
const mockZrem = vi.fn();
const mockSet = vi.fn();
const mockDel = vi.fn();
const mockPipelineGet = vi.fn();
const mockPipelineExec = vi.fn();

vi.mock('../../../../src/database/redis', () => ({
  getClientBase: () => ({
    zadd: mockZadd,
    zmscore: mockZmscore,
    zrem: mockZrem,
    set: mockSet,
    del: mockDel,
    pipeline: () => ({ get: mockPipelineGet, exec: mockPipelineExec }),
  }),
}));

import { getRuntimeData, getRuntimeDataMany, removeRuntimeData, setRuntimeData } from '../../../../src/modules/ingestionHealth/ingestionHealthRuntimeData';
import { redisString } from '../../../../src/modules/ingestionHealth/ingestionHealthRuntimeData-storage';

const HEARTBEAT = '2026-10-13T12:00:00.000Z';
const HEARTBEAT_MS = new Date(HEARTBEAT).getTime();

describe('setRuntimeData', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should store the heartbeat as the member of the connectors sorted set, scored by its epoch', async () => {
    await setRuntimeData('connector-1', 'heartbeat', HEARTBEAT);

    expect(mockZadd).toHaveBeenCalledWith('connector_heartbeats', HEARTBEAT_MS, 'connector-1');
  });

  it('should refuse a value that is not in the format of its type', async () => {
    await expect(setRuntimeData('connector-1', 'heartbeat', 'yesterday')).rejects.toThrow();

    expect(mockZadd).not.toHaveBeenCalled();
  });
});

describe('getRuntimeDataMany', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should read the heartbeat of a batch of ingestions in one call, and omit the absent ones', async () => {
    mockZmscore.mockResolvedValueOnce([String(HEARTBEAT_MS), null]);

    const result = await getRuntimeDataMany(['connector-1', 'connector-2']);

    expect(mockZmscore).toHaveBeenCalledWith('connector_heartbeats', 'connector-1', 'connector-2');
    expect(result).toEqual(new Map([['connector-1', { heartbeat: HEARTBEAT }]]));
  });

  it('should return the heartbeat as recorded, whatever its age: staleness is not judged here', async () => {
    mockZmscore.mockResolvedValueOnce([String(new Date('2000-01-01T00:00:00.000Z').getTime())]);

    expect(await getRuntimeDataMany(['connector-1'])).toEqual(new Map([['connector-1', { heartbeat: '2000-01-01T00:00:00.000Z' }]]));
  });

  it('should not call the storage without ingestion', async () => {
    expect(await getRuntimeDataMany([])).toEqual(new Map());

    expect(mockZmscore).not.toHaveBeenCalled();
  });
});

describe('getRuntimeData', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should read one ingestion, empty when it reported nothing', async () => {
    mockZmscore.mockResolvedValueOnce([String(HEARTBEAT_MS)]);
    expect(await getRuntimeData('connector-1', ['heartbeat'])).toEqual({ heartbeat: HEARTBEAT });

    mockZmscore.mockResolvedValueOnce([null]);
    expect(await getRuntimeData('connector-1')).toEqual({});
  });
});

describe('removeRuntimeData', () => {
  it('should remove the member of the ingestion', async () => {
    await removeRuntimeData('connector-1', 'heartbeat');

    expect(mockZrem).toHaveBeenCalledWith('connector_heartbeats', 'connector-1');
  });
});

describe('redisString storage', () => {
  const storage = redisString<{ a: number }>({ key: (id) => `test:{${id}}:data`, ttlSec: 60 });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should store the value as JSON, with the clean-up ttl', async () => {
    await storage.set('id-1', { a: 1 });

    expect(mockSet).toHaveBeenCalledWith('test:{id-1}:data', '{"a":1}', 'EX', 60);
  });

  it('should store the value without expiration when there is no ttl', async () => {
    await redisString<number>({ key: (id) => `test:${id}` }).set('id-1', 1);

    expect(mockSet).toHaveBeenCalledWith('test:id-1', '1');
  });

  it('should read a batch with one GET per key, and omit absent or unreadable values', async () => {
    mockPipelineExec.mockResolvedValueOnce([[null, '{"a":1}'], [null, null], [null, '{invalid']]);

    const result = await storage.getMany(['id-1', 'id-2', 'id-3']);

    expect(mockPipelineGet.mock.calls).toEqual([['test:{id-1}:data'], ['test:{id-2}:data'], ['test:{id-3}:data']]);
    expect(result).toEqual(new Map([['id-1', { a: 1 }]]));
  });

  it('should fail when a read fails, so that an unreachable storage is not read as absent data', async () => {
    const error = new Error('READONLY');
    mockPipelineExec.mockResolvedValueOnce([[error, null]]);

    await expect(storage.getMany(['id-1'])).rejects.toThrow(error);
  });

  it('should remove the key', async () => {
    await storage.remove('id-1');

    expect(mockDel).toHaveBeenCalledWith('test:{id-1}:data');
  });
});
