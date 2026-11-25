import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Middleware from '../../../../src/database/middleware';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import * as Redis from '../../../../src/database/redis';
import * as UserActionListener from '../../../../src/listener/UserActionListener';
import { SYSTEM_USER } from '../../../../src/utils/access';
import conf, { logApp, prepareLogMetadata } from '../../../../src/config/conf';
import { booleanTrueFilter } from '../../../../src/utils/filtering/filtering-utils';
import {
  checkPublicSharingsWithoutUser,
  disablePublicSharingForDeletedUser,
  findPublicSharingsWithoutUser,
  resetPublicSharingWarnings,
  resolvePublicUser,
  validatePublicUserId,
} from '../../../../src/modules/dataSharing/dataSharing-utils';

vi.mock('../../../../src/database/cache');
vi.mock('../../../../src/database/redis');
vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));
vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

describe('resolvePublicUser', () => {
  const mockContext = { source: 'testing' } as any;
  const SECURE_KEY = 'app:data_sharing:secure_by_default';
  const taxiiWithoutUser = { id: 'taxii-1', entity_type: 'TaxiiCollection', name: 'Legacy taxii', taxii_public: true } as any;
  const feedWithoutUser = { id: 'feed-1', entity_type: 'Feed', name: 'Legacy feed', feed_public: true, feed_public_user_id: null } as any;
  const streamWithoutUser = { id: 'stream-1', entity_type: 'StreamCollection', name: 'Legacy stream', stream_public: true, stream_public_user_id: '' } as any;

  beforeEach(() => {
    vi.clearAllMocks();
    resetPublicSharingWarnings();
  });
  afterEach(() => {
    conf.clear(SECURE_KEY);
  });

  it('should warn once per collection, not on every request', async () => {
    await resolvePublicUser(mockContext, taxiiWithoutUser);
    await resolvePublicUser(mockContext, taxiiWithoutUser);
    await resolvePublicUser(mockContext, feedWithoutUser);
    expect(logApp.warn).toHaveBeenCalledTimes(2);
  });

  describe('without a public user, app:data_sharing:secure_by_default=false', () => {
    it.each([
      ['a TAXII collection', taxiiWithoutUser],
      ['a CSV feed', feedWithoutUser],
      ['a live stream', streamWithoutUser],
    ])('should fall back to SYSTEM_USER for %s and warn with the collection', async (_, sharing) => {
      const result = await resolvePublicUser(mockContext, sharing);
      expect(result).toBe(SYSTEM_USER);
      expect(logApp.warn).toHaveBeenCalledWith(
        expect.stringContaining('app:data_sharing:secure_by_default=false'),
        { entity_type: sharing.entity_type, id: sharing.id, name: sharing.name },
      );
    });
  });

  describe('without a public user, app:data_sharing:secure_by_default=true', () => {
    it.each([
      ['a TAXII collection', taxiiWithoutUser, 'Taxii collection'],
      ['a CSV feed', feedWithoutUser, 'csv feed'],
      ['a live stream', streamWithoutUser, 'live stream'],
    ])('should refuse to serve %s, naming it', async (_, sharing, label) => {
      conf.set(SECURE_KEY, true);
      const promise = resolvePublicUser(mockContext, sharing);
      // The id, not the name: the message is also the reason phrase of the live stream answer, which only takes latin-1
      await expect(promise).rejects.toThrow(`The public ${label} ${sharing.id} has no public user`);
      await expect(promise).rejects.toMatchObject({ extensions: { code: 'FORBIDDEN_ACCESS', data: { http_status: 403 } } });
      expect(logApp.warn).toHaveBeenCalledWith(
        expect.stringContaining('app:data_sharing:secure_by_default=true'),
        { entity_type: sharing.entity_type, id: sharing.id, name: sharing.name },
      );
    });
  });

  it.each([false, true])('should return the configured public user whatever the switch (%s)', async (secure) => {
    conf.set(SECURE_KEY, secure);
    const realUserId = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
    const mockUser = { id: realUserId, name: 'Real User' } as any;
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[realUserId, mockUser]]) as any);

    const result = await resolvePublicUser(mockContext, { ...taxiiWithoutUser, taxii_public_user_id: realUserId });
    expect(result).toBe(mockUser);
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it('should throw FunctionalError when the public user is an internal system user', async () => {
    await expect(resolvePublicUser(mockContext, { ...streamWithoutUser, stream_public_user_id: SYSTEM_USER.id }))
      .rejects.toThrow('Cannot use an internal system user for public sharing');
  });

  it('should throw FunctionalError when the public user no longer exists in the platform cache', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    await expect(resolvePublicUser(mockContext, { ...feedWithoutUser, feed_public_user_id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa' }))
      .rejects.toThrow('The user configured for this public sharing no longer exists');
  });
});

describe('findPublicSharingsWithoutUser', () => {
  const mockContext = { source: 'testing' } as any;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should list only the public collections without a public user, of every type', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => {
      if (types?.[0] === 'Feed') {
        return [
          { id: 'feed-1', entity_type: 'Feed', name: 'Public feed without user', feed_public: true },
          { id: 'feed-2', entity_type: 'Feed', name: 'Public feed with user', feed_public: true, feed_public_user_id: 'user-id' },
          { id: 'feed-3', entity_type: 'Feed', name: 'Private feed', feed_public: false },
        ] as any;
      }
      if (types?.[0] === 'TaxiiCollection') {
        return [{ id: 'taxii-1', entity_type: 'TaxiiCollection', name: 'Public taxii without user', taxii_public: true, taxii_public_user_id: null }] as any;
      }
      if (types?.[0] === 'StreamCollection') {
        return [{ id: 'stream-1', entity_type: 'StreamCollection', name: 'Private stream', stream_public: false }] as any;
      }
      return [];
    });

    const result = await findPublicSharingsWithoutUser(mockContext);

    // Only the public ones are read
    expect(MiddlewareLoader.fullEntitiesList).toHaveBeenCalledWith(mockContext, SYSTEM_USER, ['Feed'], { filters: booleanTrueFilter('feed_public') });
    expect(result).toEqual([
      { entity_type: 'Feed', id: 'feed-1', name: 'Public feed without user' },
      { entity_type: 'TaxiiCollection', id: 'taxii-1', name: 'Public taxii without user' },
    ]);
  });
});

describe('checkPublicSharingsWithoutUser', () => {
  const mockContext = { source: 'testing' } as any;
  const SECURE_KEY = 'app:data_sharing:secure_by_default';

  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    conf.clear(SECURE_KEY);
  });

  it('should not warn when every public collection has a public user', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);
    await checkPublicSharingsWithoutUser(mockContext);
    expect(logApp.warn).not.toHaveBeenCalled();
  });

  it.each([
    [false, 'served with full access to the platform data'],
    [true, 'refused'],
  ])('should warn with the count, then each public collection without a public user (switch %s)', async (secure, verdict) => {
    conf.set(SECURE_KEY, secure);
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => {
      if (types?.[0] === 'StreamCollection') {
        return [{ id: 'stream-1', entity_type: 'StreamCollection', name: 'Legacy stream', stream_public: true }] as any;
      }
      return [];
    });

    await checkPublicSharingsWithoutUser(mockContext);

    expect(logApp.warn).toHaveBeenCalledTimes(2);
    const [message, meta] = vi.mocked(logApp.warn).mock.calls[0];
    expect(message).toContain(verdict);
    expect(message).toContain(`app:data_sharing:secure_by_default=${secure}`);
    expect(meta).toEqual({ count: 1 });
    expect(vi.mocked(logApp.warn).mock.calls[1][1]).toEqual({ collection: { entity_type: 'StreamCollection', id: 'stream-1', name: 'Legacy stream' } });
  });

  it('should log every collection, beyond the size limits of the log metadata', async () => {
    const streams = Array.from({ length: 120 }, (_, index) => ({ id: `stream-${index}`, entity_type: 'StreamCollection', name: `Legacy stream ${index}`, stream_public: true }));
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => (types?.[0] === 'StreamCollection' ? streams as any : []));

    await checkPublicSharingsWithoutUser(mockContext);

    const loggedIds = vi.mocked(logApp.warn).mock.calls.slice(1).map(([, meta]) => (prepareLogMetadata(meta) as any).collection?.id);
    expect(loggedIds).toEqual(streams.map(({ id }) => id));
  });
});

describe('validatePublicUserId', () => {
  const mockContext = { source: 'testing' } as any;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should throw when userId is an internal system user', async () => {
    await expect(validatePublicUserId(mockContext, SYSTEM_USER.id))
      .rejects.toThrow('Cannot use an internal system user for public sharing');
  });

  it('should throw when userId does not exist in the platform cache', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    await expect(validatePublicUserId(mockContext, 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa'))
      .rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should resolve without throwing when userId is valid', async () => {
    const realUserId = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[realUserId, { id: realUserId }]]) as any);
    await expect(validatePublicUserId(mockContext, realUserId)).resolves.toBeUndefined();
  });
});

describe('disablePublicSharingForDeletedUser', () => {
  const mockContext = { source: 'testing' } as any;
  const DELETED_USER_ID = 'dddddddd-dddd-4ddd-dddd-dddddddddddd';

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(Middleware.patchAttribute).mockResolvedValue({ element: { id: 'entity-id', name: 'Entity' } } as any);
    vi.mocked(UserActionListener.publishUserAction).mockResolvedValue([]);
    vi.mocked(Redis.notify).mockResolvedValue(undefined as any);
  });

  it('should do nothing when no entities reference the deleted user', async () => {
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockResolvedValue([]);

    await disablePublicSharingForDeletedUser(mockContext, DELETED_USER_ID);

    expect(Middleware.patchAttribute).not.toHaveBeenCalled();
    expect(UserActionListener.publishUserAction).not.toHaveBeenCalled();
    expect(Redis.notify).not.toHaveBeenCalled();
  });

  it('should disable a public feed referencing the deleted user (no liveField)', async () => {
    const mockFeed = { id: 'feed-1', name: 'My CSV Feed', _index: 'feeds' };
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => {
      if (types?.[0] === 'Feed') return [mockFeed] as any;
      return [];
    });

    await disablePublicSharingForDeletedUser(mockContext, DELETED_USER_ID);

    // One patchAttribute call: set feed_public=false and clear feed_public_user_id
    expect(Middleware.patchAttribute).toHaveBeenCalledTimes(1);
    expect(Middleware.patchAttribute).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      mockFeed.id,
      'Feed',
      expect.objectContaining({ feed_public: false, feed_public_user_id: null }),
      expect.objectContaining({ operations: expect.objectContaining({ feed_public_user_id: 'remove' }) }),
    );
    expect(UserActionListener.publishUserAction).toHaveBeenCalledTimes(1);
    // Feed has no EDIT_TOPIC in BUS_TOPICS, so notify is NOT called
    expect(Redis.notify).not.toHaveBeenCalled();
  });

  it('should disable a public taxii collection referencing the deleted user (no liveField)', async () => {
    const mockTaxii = { id: 'taxii-1', name: 'My Taxii', _index: 'taxii' };
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => {
      if (types?.[0] === 'TaxiiCollection') return [mockTaxii] as any;
      return [];
    });

    await disablePublicSharingForDeletedUser(mockContext, DELETED_USER_ID);

    expect(Middleware.patchAttribute).toHaveBeenCalledTimes(1);
    expect(Middleware.patchAttribute).toHaveBeenCalledWith(
      mockContext,
      SYSTEM_USER,
      mockTaxii.id,
      'TaxiiCollection',
      expect.objectContaining({ taxii_public: false, taxii_public_user_id: null }),
      expect.anything(),
    );
    expect(UserActionListener.publishUserAction).toHaveBeenCalledTimes(1);
    expect(Redis.notify).toHaveBeenCalledTimes(1);
  });

  it('should disable a public stream collection and stop the live stream (with liveField)', async () => {
    const mockStream = { id: 'stream-1', name: 'My Live Stream', _index: 'streams' };
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => {
      if (types?.[0] === 'StreamCollection') return [mockStream] as any;
      return [];
    });

    await disablePublicSharingForDeletedUser(mockContext, DELETED_USER_ID);

    // Two patchAttribute calls: first to stop stream_live, second to make it private
    expect(Middleware.patchAttribute).toHaveBeenCalledTimes(2);
    expect(Middleware.patchAttribute).toHaveBeenNthCalledWith(
      1,
      mockContext,
      SYSTEM_USER,
      mockStream.id,
      'StreamCollection',
      { stream_live: false },
    );
    expect(Middleware.patchAttribute).toHaveBeenNthCalledWith(
      2,
      mockContext,
      SYSTEM_USER,
      mockStream.id,
      'StreamCollection',
      expect.objectContaining({ stream_public: false, stream_public_user_id: null }),
      expect.anything(),
    );
    expect(UserActionListener.publishUserAction).toHaveBeenCalledTimes(2);
    expect(Redis.notify).toHaveBeenCalledTimes(2);
  });

  it('should handle multiple entity types in parallel and disable all found entities', async () => {
    const mockFeed = { id: 'feed-1', name: 'Feed 1', _index: 'feeds' };
    const mockTaxii = { id: 'taxii-1', name: 'Taxii 1', _index: 'taxii' };
    const mockStream = { id: 'stream-1', name: 'Stream 1', _index: 'streams' };
    vi.mocked(MiddlewareLoader.fullEntitiesList).mockImplementation(async (_ctx, _user, types) => {
      if (types?.[0] === 'Feed') return [mockFeed] as any;
      if (types?.[0] === 'TaxiiCollection') return [mockTaxii] as any;
      if (types?.[0] === 'StreamCollection') return [mockStream] as any;
      return [];
    });

    await disablePublicSharingForDeletedUser(mockContext, DELETED_USER_ID);

    // feed: 1 patch (no notify), taxii: 1 patch + 1 notify, stream: 2 patches + 2 notifies = 4 patches total
    expect(Middleware.patchAttribute).toHaveBeenCalledTimes(4);
    // feed: 1 action, taxii: 1 action, stream: 2 actions = 4 total
    expect(UserActionListener.publishUserAction).toHaveBeenCalledTimes(4);
    // feed: 0 notify (no EDIT_TOPIC), taxii: 1 notify, stream: 2 notifies = 3 total
    expect(Redis.notify).toHaveBeenCalledTimes(3);
  });
});
