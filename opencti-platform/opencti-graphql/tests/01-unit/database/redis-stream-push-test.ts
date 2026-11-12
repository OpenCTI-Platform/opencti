import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { ActivityStreamEvent, BaseEvent, StreamNotifEvent } from '../../../src/types/event';

// Shared mocks referenced by the (per-scenario) module factories below.
const mockClient = { xadd: vi.fn(), xinfo: vi.fn(), xrange: vi.fn() };
const mockRawUpload = vi.fn();
const mockGetFileContent = vi.fn();
const mockLogWarn = vi.fn();

// The offloading / trimming thresholds are read from `conf` at module-load time
// (const streamMaxEventSize / streamTrimming). To exercise both branches we reset the
// module registry and re-import redis-stream with a stubbed conf that returns the desired
// thresholds. Heavy transitive dependencies (stream-utils and its STIX/schema graph,
// database/utils, format) are stubbed so each re-import stays cheap and fast.
const loadModule = async (maxEventSize: number, trimming: number) => {
  vi.resetModules();

  vi.doMock('../../../src/database/redis', () => ({
    getClientBase: () => mockClient,
    getClientXRANGE: () => mockClient,
    createRedisClient: vi.fn(),
  }));

  vi.doMock('../../../src/database/raw-file-storage', () => ({
    rawUpload: mockRawUpload,
    getFileContent: mockGetFileContent,
  }));

  vi.doMock('../../../src/config/conf', () => ({
    default: {
      get: (key: string) => {
        if (key === 'redis:max_event_length') return maxEventSize;
        if (key === 'redis:trimming') return trimming;
        return 0;
      },
    },
    logApp: { info: vi.fn(), debug: vi.fn(), error: vi.fn(), warn: mockLogWarn },
    REDIS_PREFIX: 'test:',
  }));

  // Avoid pulling in the heavy STIX/schema graph that stream-utils transitively imports:
  // redis-stream only needs the stream-name constants from it at runtime.
  vi.doMock('../../../src/database/stream/stream-utils', () => ({
    LIVE_STREAM_NAME: 'stream.opencti',
    NOTIFICATION_STREAM_NAME: 'stream.notification',
    ACTIVITY_STREAM_NAME: 'stream.activity',
  }));

  vi.doMock('../../../src/database/utils', () => ({
    isEmptyField: (v: unknown) => v === undefined || v === null || v === '',
    wait: vi.fn(),
    waitInSec: vi.fn(),
  }));

  vi.doMock('../../../src/utils/format', () => ({
    streamEventId: (date: number | null = null, index = 0) => `${date ?? Date.now()}-${index}`,
    utcDate: (v: unknown) => ({ toISOString: () => new Date(v as number).toISOString() }),
  }));

  return import('../../../src/database/redis-stream');
};

// Reproduce mapJSToStream ordering: [key, JSON.stringify(value), ...] in Object.keys order.
const toStreamFields = (event: Record<string, unknown>): string[] => {
  const fields: string[] = [];
  Object.keys(event).forEach((key) => {
    if (event[key] !== undefined) {
      fields.push(key, JSON.stringify(event[key]));
    }
  });
  return fields;
};

type RedisStreamModule = typeof import('../../../src/database/redis-stream');

describe('rawPushToStream', () => {
  describe('without trimming (offload threshold = 50 bytes)', () => {
    let mod: RedisStreamModule;

    beforeAll(async () => {
      mod = await loadModule(50, 0);
    }, 60000);

    afterEach(() => {
      vi.clearAllMocks();
    });

    it('pushes a small event inline with a plain XADD (no MAXLEN, no S3 offload)', async () => {
      const event = { type: 'create', scope: 'external' } as unknown as BaseEvent;
      await mod.rawPushToStream(event);

      // No offloading for a sub-threshold event
      expect(mockRawUpload).not.toHaveBeenCalled();

      // A single XADD carrying the serialized fields, without MAXLEN trimming
      expect(mockClient.xadd).toHaveBeenCalledTimes(1);
      const args = mockClient.xadd.mock.calls[0];
      expect(args[0]).toBe('stream.opencti');
      expect(args[1]).toBe('*');
      expect(args.slice(2)).toEqual(toStreamFields(event as unknown as Record<string, unknown>));
    });

    it('offloads a large event to S3 and stores only the file reference in the stream', async () => {
      const event = { type: 'create', scope: 'external', data: { id: 'x'.repeat(300) } } as unknown as BaseEvent;
      const expectedFields = toStreamFields(event as unknown as Record<string, unknown>);

      await mod.rawPushToStream(event);

      // The oversized event is uploaded to S3 under the stream file directory
      expect(mockRawUpload).toHaveBeenCalledTimes(1);
      const [uploadPath, uploadContent] = mockRawUpload.mock.calls[0];
      expect(uploadPath.startsWith(mod.STREAM_FILE_DIRECTORY)).toBe(true);
      // The uploaded body is the JSON-serialized original stream fields
      expect(uploadContent).toBe(JSON.stringify(expectedFields));

      // The stream entry only keeps the file pointer, not the full payload
      expect(mockClient.xadd).toHaveBeenCalledTimes(1);
      const args = mockClient.xadd.mock.calls[0];
      expect(args[1]).toBe('*');
      expect(args.slice(2)).toEqual(['event_file_id', uploadPath]);
    });

    it('does not offload an event whose size is exactly at the threshold', async () => {
      // Build an event whose serialized fields total exactly 50 bytes (threshold is strict: > 50 offloads)
      // fields = ['type', '"..."'] -> 'type'(4) + '"' + value + '"' must sum to 50 => value length = 44
      const event = { type: 'a'.repeat(44) } as unknown as BaseEvent;
      const size = toStreamFields(event as unknown as Record<string, unknown>).join('').length;
      expect(size).toBe(50); // sanity: exactly at threshold

      await mod.rawPushToStream(event);

      expect(mockRawUpload).not.toHaveBeenCalled();
      expect(mockClient.xadd.mock.calls[0].slice(2)).toEqual(toStreamFields(event as unknown as Record<string, unknown>));
    });
  });

  describe('with trimming enabled', () => {
    let mod: RedisStreamModule;

    beforeAll(async () => {
      mod = await loadModule(0, 1000);
    }, 60000);

    afterEach(() => {
      vi.clearAllMocks();
    });

    it('adds a MAXLEN approximate trimming directive to the XADD', async () => {
      const event = { type: 'create', scope: 'external' } as unknown as BaseEvent;
      await mod.rawPushToStream(event);

      expect(mockClient.xadd).toHaveBeenCalledTimes(1);
      const args = mockClient.xadd.mock.calls[0];
      expect(args[1]).toBe('MAXLEN');
      expect(args[2]).toBe('~');
      expect(args[3]).toBe(1000);
      expect(args[4]).toBe('*');
      expect(args.slice(5)).toEqual(toStreamFields(event as unknown as Record<string, unknown>));
    });

    it('never offloads to S3 when max_event_length is disabled (0), regardless of size', async () => {
      const event = { type: 'create', data: { id: 'x'.repeat(5000) } } as unknown as BaseEvent;
      await mod.rawPushToStream(event);
      expect(mockRawUpload).not.toHaveBeenCalled();
    });
  });
});

describe('processStreamData', () => {
  let mod: RedisStreamModule;

  beforeAll(async () => {
    mod = await loadModule(50, 0);
  }, 60000);

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('maps an inline event (no file reference) without touching S3', async () => {
    const fields = ['type', JSON.stringify('create'), 'scope', JSON.stringify('external'), 'data', JSON.stringify({ id: 'obj-1' })];
    const result = await mod.processStreamData(['100-0', fields]);

    expect(mockGetFileContent).not.toHaveBeenCalled();
    expect(result).toEqual({
      id: '100-0',
      event: 'create',
      data: { type: 'create', scope: 'external', data: { id: 'obj-1' } },
    });
  });

  it('resolves an offloaded event by fetching and parsing its S3 file', async () => {
    const storedFields = ['type', JSON.stringify('create'), 'scope', JSON.stringify('external'), 'data', JSON.stringify({ id: 'obj-2' })];
    mockGetFileContent.mockResolvedValueOnce(JSON.stringify(storedFields));

    const result = await mod.processStreamData(['200-0', ['event_file_id', 'streams/stream.opencti/200-0']]);

    expect(mockGetFileContent).toHaveBeenCalledWith('streams/stream.opencti/200-0');
    expect(result).toEqual({
      id: '200-0',
      event: 'create',
      data: { type: 'create', scope: 'external', data: { id: 'obj-2' } },
    });
  });

  it('returns null and warns when the offloaded file is missing', async () => {
    mockGetFileContent.mockResolvedValueOnce(undefined);

    const result = await mod.processStreamData(['300-0', ['event_file_id', 'streams/stream.opencti/300-0']]);

    expect(result).toBeNull();
    expect(mockLogWarn).toHaveBeenCalledWith(
      'Stream event file could not be found',
      expect.objectContaining({ id: '300-0', filePath: 'streams/stream.opencti/300-0' }),
    );
  });

  it('returns null and warns when fetching the offloaded file throws', async () => {
    mockGetFileContent.mockRejectedValueOnce(new Error('S3 down'));

    const result = await mod.processStreamData(['400-0', ['event_file_id', 'streams/stream.opencti/400-0']]);

    expect(result).toBeNull();
    expect(mockLogWarn).toHaveBeenCalledWith(
      'Error fetching file stream event, skipping event',
      expect.objectContaining({ id: '400-0', filePath: 'streams/stream.opencti/400-0' }),
    );
  });
});

describe('stream commands', () => {
  let mod: RedisStreamModule;

  beforeAll(async () => {
    mod = await loadModule(0, 0);
  }, 60000);

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('reads the stream info with the namespaced key and parses the reply', async () => {
    mockClient.xinfo.mockResolvedValueOnce([
      'length', 2,
      'first-entry', ['1000-0', ['type', '"create"']],
      'last-entry', ['2000-0', ['type', '"update"']],
    ]);

    const info = await mod.rawFetchStreamInfo();

    expect(mockClient.xinfo).toHaveBeenCalledWith('STREAM', 'test:stream.opencti');
    expect(info).toEqual({
      firstEventId: '1000-0',
      firstEventDate: new Date(1000).toISOString(),
      lastEventId: '2000-0',
      lastEventDate: new Date(2000).toISOString(),
      streamSize: 2,
    });
  });

  it('rejects an unknown stream name', async () => {
    await expect(mod.rawFetchStreamInfo('stream.unknown')).rejects.toThrow('Cannot recognize stream name');
    expect(mockClient.xinfo).not.toHaveBeenCalled();
  });

  it('stores notification and activity events with the bare stream name', async () => {
    const notification = { type: 'live', notification_id: 'trigger-A' } as unknown as StreamNotifEvent;
    const activity = { type: 'authentication', event_scope: 'login' } as unknown as ActivityStreamEvent;

    await mod.rawRedisStreamClient.rawStoreNotificationEvent(notification);
    await mod.rawRedisStreamClient.rawStoreActivityEvent(activity);

    expect(mockClient.xadd).toHaveBeenNthCalledWith(1, 'stream.notification', 'MAXLEN', '~', 50000, '*', ...toStreamFields(notification as unknown as Record<string, unknown>));
    expect(mockClient.xadd).toHaveBeenNthCalledWith(2, 'stream.activity', 'MAXLEN', '~', 50000, '*', ...toStreamFields(activity as unknown as Record<string, unknown>));
  });

  it('fetches a live stream range after the given event id', async () => {
    const fields = ['type', JSON.stringify('create'), 'scope', JSON.stringify('external')];
    mockClient.xrange.mockResolvedValueOnce([['1001-0', fields], ['1002-0', fields]]);
    const callback = vi.fn();

    const result = await mod.rawRedisStreamClient.rawFetchStreamEventsRangeFromEventId('1000-0', callback, { streamBatchSize: 10 });

    expect(mockClient.xrange).toHaveBeenCalledWith('stream.opencti', '(1000-0', '+', 'COUNT', 10);
    expect(callback).toHaveBeenCalledWith(
      [expect.objectContaining({ id: '1001-0' }), expect.objectContaining({ id: '1002-0' })],
      '1002-0',
    );
    expect(result).toEqual({ lastEventId: '1002-0' });
  });
});
