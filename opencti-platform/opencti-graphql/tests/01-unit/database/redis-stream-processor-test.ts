import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const steps: string[] = [];
let rejectPendingRead: ((error: Error) => void) | undefined;
const mockClient = {
  call: vi.fn(),
  disconnect: vi.fn(() => rejectPendingRead?.(new Error('disconnected'))),
};

// Same stubbing approach as redis-stream-push-test: keep the heavy transitive dependencies out of the import,
// and record every wait and yield of the processing loop in `steps`, next to the callback invocations.
const loadModule = async () => {
  vi.resetModules();

  vi.doMock('../../../src/database/redis', () => ({
    getClientBase: () => mockClient,
    getClientXRANGE: () => mockClient,
    createRedisClient: async () => mockClient,
  }));

  vi.doMock('../../../src/database/raw-file-storage', () => ({
    rawUpload: vi.fn(),
    getFileContent: vi.fn(),
  }));

  vi.doMock('../../../src/config/conf', () => ({
    default: { get: () => 0 },
    logApp: { info: vi.fn(), debug: vi.fn(), error: vi.fn(), warn: vi.fn() },
    REDIS_PREFIX: '',
  }));

  vi.doMock('../../../src/database/stream/stream-utils', () => ({
    LIVE_STREAM_NAME: 'stream.opencti',
    NOTIFICATION_STREAM_NAME: 'stream.notification',
    ACTIVITY_STREAM_NAME: 'stream.activity',
  }));

  vi.doMock('../../../src/database/utils', () => ({
    isEmptyField: (v: unknown) => v === undefined || v === null || v === '',
    wait: async (ms: number) => {
      steps.push(`wait:${ms}`);
    },
    waitInSec: vi.fn(),
  }));

  vi.doMock('../../../src/utils/eventloop-utils', () => ({
    doYield: async () => {
      steps.push('yield');
      return false;
    },
  }));

  // asyncMap calls doYield for every entry: replace it so that only the yields of the processing loop are recorded
  vi.doMock('../../../src/utils/data-processing', () => ({
    asyncMap: async <T, Z>(elements: T[], transform: (value: T) => Z | Promise<Z>, filter?: (value: Z) => boolean) => {
      const transformed: Z[] = [];
      for (let index = 0; index < elements.length; index += 1) {
        const item = await transform(elements[index]);
        if (!filter || filter(item)) {
          transformed.push(item);
        }
      }
      return transformed;
    },
  }));

  vi.doMock('../../../src/utils/format', () => ({
    streamEventId: (date: number | null = null, index = 0) => `${date ?? Date.now()}-${index}`,
    utcDate: (v: unknown) => ({ toISOString: () => new Date(v as number).toISOString() }),
  }));

  return import('../../../src/database/redis-stream');
};

const buildEntries = (count: number, offset = 0) => {
  return Array.from({ length: count }, (_, index) => [
    `${1000 + offset + index}-0`,
    ['type', JSON.stringify('create'), 'scope', JSON.stringify('external')],
  ]);
};

// Serve the given XREAD results in order, then block like an idle stream until the client is disconnected.
const serveReads = (batchSizes: number[]) => {
  let reachedIdle: () => void = () => {};
  const idle = new Promise<void>((resolve) => {
    reachedIdle = resolve;
  });
  let offset = 0;
  mockClient.call.mockReset();
  batchSizes.forEach((size) => {
    mockClient.call.mockResolvedValueOnce([['stream.opencti', buildEntries(size, offset)]]);
    offset += size;
  });
  mockClient.call.mockImplementationOnce(() => new Promise((_, reject) => {
    rejectPendingRead = reject;
    reachedIdle();
  }));
  return idle;
};

type RedisStreamModule = typeof import('../../../src/database/redis-stream');

describe('rawCreateStreamProcessor', () => {
  let mod: RedisStreamModule;

  beforeAll(async () => {
    mod = await loadModule();
  }, 60000);

  beforeEach(() => {
    steps.length = 0;
    rejectPendingRead = undefined;
  });

  const runProcessor = async (batchSizes: number[], bufferTime?: number) => {
    const idle = serveReads(batchSizes);
    const callback = async (events: Array<unknown>) => {
      steps.push(`callback:${events.length}`);
    };
    const processor = mod.rawRedisStreamClient.rawCreateStreamProcessor('test', callback, { bufferTime });
    await processor.start('0-0');
    await idle;
    await processor.shutdown();
  };

  it('reads again right away after a full batch and waits bufferTime after a partial one', async () => {
    await runProcessor([100, 3], 5000);
    expect(steps).toEqual(['callback:100', 'yield', 'callback:3', 'wait:5000']);
  });

  it('waits the default bufferTime after a partial batch', async () => {
    await runProcessor([3]);
    expect(steps).toEqual(['callback:3', 'wait:50']);
  });

  it('only yields after every batch when bufferTime is 0', async () => {
    await runProcessor([100, 3], 0);
    expect(steps).toEqual(['callback:100', 'yield', 'callback:3', 'yield']);
  });
});
