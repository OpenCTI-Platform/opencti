import { EventEmitter } from 'events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AbortError } from 'node-fetch';

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

import { logApp } from '../../../src/config/conf';
import { ClientAbortError, DatabaseError } from '../../../src/config/errors';
import { elList } from '../../../src/database/engine';
import { createStreamProcessor } from '../../../src/database/stream/stream-handler';
// eslint-disable-next-line import/extensions
import createSseMiddleware from '../../../src/graphql/sseMiddleware.js';

const STREAM_ID = 'live-stream-id';

const makeResponse = () => {
  const res: any = new EventEmitter();
  res.writable = true;
  res.finished = false;
  res.writableLength = 0;
  res.writableHighWaterMark = 16384;
  res.writeHead = vi.fn();
  res.write = vi.fn(() => true);
  res.flush = vi.fn();
  res.end = vi.fn();
  res.status = vi.fn(() => res);
  return res;
};

const writtenTopics = (res: any) => res.write.mock.calls
  .map(([message]: [string]) => /^event: (.+)$/m.exec(message)?.[1])
  .filter((topic: string | undefined) => topic !== undefined);

// Opens a live stream that has to recover from history, so the engine is queried before the live processing starts
const openRecoveringLiveStream = async (res: any) => {
  const app = { get: vi.fn(), post: vi.fn() };
  const middleware = createSseMiddleware();
  middleware.applyMiddleware({ app });
  const [, , liveStreamHandler] = app.get.mock.calls.find(([path]) => path.endsWith('/stream/:id'))!;
  const req: any = new EventEmitter();
  req.params = { id: STREAM_ID };
  req.query = { from: '2020-01-01T00:00:00.000Z', recover: '2021-01-01T00:00:00.000Z' };
  req.headers = {};
  req.user = { id: 'user-id', user_email: 'user@opencti.io' };
  req.context = {};
  await liveStreamHandler(req, res);
  return middleware;
};

describe('Live stream failure while recovering', () => {
  let middleware: ReturnType<typeof createSseMiddleware> | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createStreamProcessor).mockReturnValue({ info: async () => ({}), start: vi.fn(), shutdown: vi.fn() } as any);
  });

  afterEach(() => {
    middleware?.shutdown();
  });

  it('should log a client disconnection at info and not send an error event', async () => {
    const abortCause = new AbortError('The http call was aborted before el request started.');
    vi.mocked(elList).mockRejectedValue(ClientAbortError('Fail to execute engine pagination', { cause: abortCause }));
    const res = makeResponse();

    middleware = await openRecoveringLiveStream(res);

    expect(logApp.error).not.toHaveBeenCalled();
    expect(logApp.info).toHaveBeenCalledWith('[STREAM] Client disconnected during processing', expect.objectContaining({ id: STREAM_ID, type: 'live' }));
    expect(writtenTopics(res)).toEqual(['connected']);
  });

  it('should treat a raw engine client abort the same way', async () => {
    vi.mocked(elList).mockRejectedValue(new AbortError('The http call was aborted before el request started.'));
    const res = makeResponse();

    middleware = await openRecoveringLiveStream(res);

    expect(logApp.error).not.toHaveBeenCalled();
    expect(writtenTopics(res)).toEqual(['connected']);
  });

  it('should keep logging a genuine engine failure at error and send the error event', async () => {
    vi.mocked(elList).mockRejectedValue(DatabaseError('Fail to execute engine pagination', { cause: new Error('engine unavailable') }));
    const res = makeResponse();

    middleware = await openRecoveringLiveStream(res);

    expect(logApp.error).toHaveBeenCalledWith('[STREAM] Processing error', expect.objectContaining({ id: STREAM_ID, type: 'live' }));
    expect(writtenTopics(res)).toEqual(['connected', 'error']);
  });
});
