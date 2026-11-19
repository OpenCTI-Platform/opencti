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
vi.mock('../../../src/database/cache', () => ({ getEntitiesListFromCache: vi.fn(), getEntitiesMapFromCache: vi.fn(), getEntityFromCache: vi.fn() }));
vi.mock('../../../src/database/stix-2-1-converter', () => ({ convertStoreToStix_2_1: vi.fn((instance) => instance) }));
vi.mock('../../../src/database/data-changes', () => ({ generateCreateMessage: vi.fn(() => 'creates') }));
vi.mock('../../../src/utils/filtering/filtering-stix/stix-filtering', () => ({ isStixMatchFilterGroup: vi.fn() }));
// The recovered elements have no ref to resolve
vi.mock('../../../src/schema/stixEmbeddedRelationship', () => ({ stixRefsExtractor: vi.fn(() => []) }));
vi.mock('../../../src/graphql/streamConsumerRegistry', () => ({
  registerConsumer: vi.fn(),
  unregisterConsumer: vi.fn(async () => {}),
  trackEventDelivered: vi.fn(),
  trackEventsProcessed: vi.fn(),
  trackMissingResolution: vi.fn(),
}));

import { createStreamProcessor } from '../../../src/database/stream/stream-handler';
import { elList } from '../../../src/database/engine';
import { storeLoadByIdsWithRefs } from '../../../src/database/middleware';
import { getEntitiesListFromCache, getEntitiesMapFromCache, getEntityFromCache } from '../../../src/database/cache';
import { isStixMatchFilterGroup } from '../../../src/utils/filtering/filtering-stix/stix-filtering';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
// eslint-disable-next-line import/extensions
import createSseMiddleware from '../../../src/graphql/sseMiddleware.js';

const STREAM_ID = 'stream-id';
const EMPTY_FILTERS = JSON.stringify({ mode: 'and', filters: [], filterGroups: [] });

const buildUser = (overrides: Record<string, any> = {}) => ({
  id: 'user-id',
  internal_id: 'user-id',
  user_email: 'user@opencti.io',
  account_status: 'Active',
  capabilities: [{ name: 'TAXIIAPI' }],
  allowed_marking: [],
  organizations: [],
  ...overrides,
});

const buildCollection = (overrides: Record<string, any> = {}) => ({
  id: STREAM_ID,
  stream_live: true,
  stream_public: false,
  filters: EMPTY_FILTERS,
  restricted_members: [],
  ...overrides,
});

// An element listed by the recovery, and the same element once loaded (STIX conversion is mocked as identity)
const listed = (id: string) => ({ internal_id: id, standard_id: `malware--${id}` });
const loaded = (id: string) => ({
  id: `malware--${id}`,
  type: 'malware',
  extensions: { [STIX_EXT_OCTI]: { id, type: 'Malware', updated_at: '2026-01-15T00:00:00.000Z' } },
});

const mockPlatformUsers = (...users: any[]) => {
  vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map(users.map((u) => [u.id, u])) as any);
};
const mockCollection = (collection: any) => {
  vi.mocked(getEntitiesListFromCache).mockResolvedValue([collection] as any);
};

const makeResponse = () => {
  const res: any = new EventEmitter();
  res.writable = true;
  res.finished = false;
  res.writableLength = 0;
  res.writableHighWaterMark = 16384;
  res.writeHead = vi.fn();
  res.write = vi.fn(() => true);
  res.flush = vi.fn();
  res.status = vi.fn(() => res);
  res.end = vi.fn(() => {
    res.finished = true;
    res.writable = false;
  });
  return res;
};

const publishedIds = (res: any) => res.write.mock.calls
  .map(([message]: [string]) => message)
  .filter((message: string) => message.includes('event: create'))
  .map((message: string) => JSON.parse(message.split('data: ')[1]).data.id);

let middleware: ReturnType<typeof createSseMiddleware> | undefined;

const openLiveStream = async (res: any, { user, collection, query = {} }: { user: any; collection: any; query?: Record<string, string> }) => {
  const app = { get: vi.fn(), post: vi.fn() };
  middleware = createSseMiddleware();
  middleware.applyMiddleware({ app });
  const [, , liveStreamHandler] = app.get.mock.calls.find(([path]) => path.endsWith('/stream/:id'))!;
  const req: any = new EventEmitter();
  req.params = { id: STREAM_ID };
  req.query = { 'no-dependencies': 'true', ...query };
  req.headers = {};
  req.user = user;
  req.userId = user.id;
  req.context = { user: collection.stream_public ? undefined : user };
  req.collection = collection;
  req.streamFilters = JSON.parse(collection.filters);
  req.originFilters = null;
  await liveStreamHandler(req, res);
  return req;
};

const RECOVERY_QUERY = { from: '2026-01-01T00:00:00.000Z', recover: '2026-02-01T00:00:00.000Z' };

describe('Live stream access refresh', () => {
  const processor = { info: vi.fn(async () => ({})), start: vi.fn(), shutdown: vi.fn() };
  // Batch callback the live stream gives to its processor
  const liveBatch = () => vi.mocked(createStreamProcessor).mock.calls[0][1] as (elements: any[], lastEventId: string) => Promise<void>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(createStreamProcessor).mockReturnValue(processor as any);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: undefined } as any);
  });

  afterEach(() => {
    middleware?.shutdown();
    middleware = undefined;
  });

  it('should close the live stream once the account of its user is locked', async () => {
    const user = buildUser();
    mockPlatformUsers(user);
    mockCollection(buildCollection());
    const res = makeResponse();
    await openLiveStream(res, { user, collection: buildCollection() });
    await liveBatch()([], '1767225600000-0');
    expect(res.end).not.toHaveBeenCalled();

    mockPlatformUsers({ ...user, account_status: 'Locked' });
    await liveBatch()([], '1767225600001-0');

    expect(res.end).toHaveBeenCalled();
  });

  it('should close a public stream once it is served for another public user', async () => {
    const publicUser = buildUser({ id: 'public-a', internal_id: 'public-a' });
    const collection = buildCollection({ stream_public: true, stream_public_user_id: 'public-a' });
    mockPlatformUsers(publicUser);
    mockCollection(collection);
    const res = makeResponse();
    await openLiveStream(res, { user: publicUser, collection });
    await liveBatch()([], '1767225600000-0');
    expect(res.end).not.toHaveBeenCalled();

    mockCollection({ ...collection, stream_public_user_id: 'public-b' });
    await liveBatch()([], '1767225600001-0');

    expect(res.end).toHaveBeenCalled();
  });

  it('should close a public stream once it is made private', async () => {
    // The public user would pass the checks of a private stream
    const publicUser = buildUser({ id: 'public-a', internal_id: 'public-a' });
    const collection = buildCollection({ stream_public: true, stream_public_user_id: 'public-a' });
    mockPlatformUsers(publicUser);
    mockCollection(collection);
    const res = makeResponse();
    await openLiveStream(res, { user: publicUser, collection });

    mockCollection({ ...collection, stream_public: false });
    await liveBatch()([], '1767225600000-0');

    expect(res.end).toHaveBeenCalled();
  });

  it('should stop the recovery, without listening the live stream, once its user no longer exists', async () => {
    const user = buildUser();
    mockPlatformUsers(user);
    mockCollection(buildCollection());
    vi.mocked(storeLoadByIdsWithRefs).mockResolvedValue([loaded('a')] as any);
    const batchResults: boolean[] = [];
    vi.mocked(elList).mockImplementation(async (_context, _user, _indices, options: any) => {
      batchResults.push(await options.callback([listed('a')]));
      mockPlatformUsers();
      batchResults.push(await options.callback([listed('b')]));
      return [];
    });
    const res = makeResponse();

    await openLiveStream(res, { user, collection: buildCollection(), query: RECOVERY_QUERY });

    expect(batchResults).toEqual([true, false]);
    expect(storeLoadByIdsWithRefs).toHaveBeenCalledTimes(1);
    expect(publishedIds(res)).toEqual(['malware--a']);
    expect(res.end).toHaveBeenCalled();
    expect(processor.start).not.toHaveBeenCalled();
  });

  it('should check again what was already published once the user changed', async () => {
    const user = buildUser();
    mockPlatformUsers(user);
    mockCollection(buildCollection());
    vi.mocked(storeLoadByIdsWithRefs).mockResolvedValue([loaded('a')] as any);
    vi.mocked(elList).mockImplementation(async (_context, _user, _indices, options: any) => {
      await options.callback([listed('a')]);
      // Same user: what was published is trusted
      await options.callback([listed('a')]);
      // The users cache gives a new object for the user: its rights may have changed
      mockPlatformUsers({ ...user });
      await options.callback([listed('a')]);
      return [];
    });
    const res = makeResponse();

    await openLiveStream(res, { user, collection: buildCollection(), query: RECOVERY_QUERY });

    const loadedIds = vi.mocked(storeLoadByIdsWithRefs).mock.calls.map(([, , ids]) => ids);
    expect(loadedIds).toEqual([['a'], [], ['a']]);
    expect(processor.start).toHaveBeenCalled();
  });

  it('should only recover the elements matching the filters once they changed during the recovery', async () => {
    const user = buildUser();
    mockPlatformUsers(user);
    mockCollection(buildCollection());
    vi.mocked(isStixMatchFilterGroup).mockResolvedValue(false);
    vi.mocked(storeLoadByIdsWithRefs).mockImplementation(async (_context, _user, ids) => (ids as string[]).map(loaded) as any);
    vi.mocked(elList).mockImplementation(async (_context, _user, _indices, options: any) => {
      await options.callback([listed('a')]);
      // Filters narrowed: the elements listed with the previous ones are checked again
      mockCollection(buildCollection({ filters: JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'] }], filterGroups: [] }) }));
      await options.callback([listed('b')]);
      return [];
    });
    const res = makeResponse();

    await openLiveStream(res, { user, collection: buildCollection(), query: RECOVERY_QUERY });

    expect(isStixMatchFilterGroup).toHaveBeenCalledTimes(1);
    expect(publishedIds(res)).toEqual(['malware--a']);
  });
});
