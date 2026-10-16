import { EventEmitter } from 'events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../src/config/conf');
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), debug: vi.fn(), warn: vi.fn() },
  };
});
vi.mock('../../../src/database/redis');
vi.mock('../../../src/database/stream/stream-handler', () => ({ createStreamProcessor: vi.fn() }));
vi.mock('../../../src/database/engine', () => ({ elCount: vi.fn(), elList: vi.fn(), elFindByIds: vi.fn() }));
vi.mock('../../../src/database/middleware-loader', () => ({ fullRelationsList: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ stixLoadById: vi.fn(), storeLoadByIdsWithRefs: vi.fn() }));
vi.mock('../../../src/database/cache', () => ({ getEntitiesListFromCache: vi.fn(), getEntityFromCache: vi.fn() }));
vi.mock('../../../src/graphql/streamConsumerRegistry', () => ({
  registerConsumer: vi.fn(),
  unregisterConsumer: vi.fn(async () => {}),
  trackEventDelivered: vi.fn(),
  trackEventsProcessed: vi.fn(),
  trackMissingResolution: vi.fn(),
}));
vi.mock('../../../src/modules/dataSharing/streamCollection-domain', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/modules/dataSharing/streamCollection-domain')>();
  return { ...actual, getStreamConsumerInformation: vi.fn(async () => ({ connectionId: 'mock' })) };
});
vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/utils/access')>();
  return { ...actual, isUserHasCapability: vi.fn(() => true) };
});

import { createStreamProcessor } from '../../../src/database/stream/stream-handler';
import { getStreamConsumerInformation } from '../../../src/modules/dataSharing/streamCollection-domain';
// eslint-disable-next-line import/extensions
import createSseMiddleware from '../../../src/graphql/sseMiddleware.js';

const HEARTBEAT_PERIOD = 5000;

// Response of a consumer that stopped reading: every write is buffered and drain never comes
const makeStalledResponse = (writableLength: number) => {
  const res: any = new EventEmitter();
  res.writable = true;
  res.finished = false;
  res.writableLength = writableLength;
  res.writableHighWaterMark = 16384;
  res.writeHead = vi.fn();
  res.write = vi.fn(() => false);
  res.flush = vi.fn();
  res.end = vi.fn();
  return res;
};

const openGenericStream = (res: any) => {
  const app = { get: vi.fn(), post: vi.fn() };
  const middleware = createSseMiddleware();
  middleware.applyMiddleware({ app });
  const [, , genericStreamHandler] = app.get.mock.calls.find(([path]) => path.endsWith('/stream'))!;
  const req: any = new EventEmitter();
  req.query = { from: '1760393940000-0' };
  req.headers = {};
  req.user = { id: 'user-id', user_email: 'user@opencti.io' };
  req.context = {};
  // Not awaited: the handler waits for the stalled consumer to drain its connected event
  genericStreamHandler(req, res);
  return middleware;
};

describe('SSE heartbeat with a stalled consumer', () => {
  let middleware: ReturnType<typeof createSseMiddleware> | undefined;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(createStreamProcessor).mockReturnValue({ info: async () => ({}), start: vi.fn(), shutdown: vi.fn() } as any);
    vi.mocked(getStreamConsumerInformation).mockClear();
  });

  afterEach(() => {
    middleware?.shutdown();
    vi.useRealTimers();
  });

  it('should not queue heartbeat nor metrics while the socket buffer is not empty', async () => {
    const res = makeStalledResponse(1024);
    middleware = openGenericStream(res);
    await vi.advanceTimersByTimeAsync(HEARTBEAT_PERIOD * 12);
    // Only the connected event is waiting for drain
    expect(res.write).toHaveBeenCalledTimes(1);
    expect(res.listenerCount('drain')).toBe(1);
    expect(getStreamConsumerInformation).not.toHaveBeenCalled();
  });

  it('should not start a new tick while the previous heartbeat is still waiting for drain', async () => {
    const res = makeStalledResponse(0);
    middleware = openGenericStream(res);
    await vi.advanceTimersByTimeAsync(HEARTBEAT_PERIOD * 12);
    // The connected event and a single heartbeat are waiting for drain, nothing else accumulated
    expect(res.write).toHaveBeenCalledTimes(2);
    expect(res.listenerCount('drain')).toBe(2);
  });
});
