import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Middleware from '../../../../src/database/middleware';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import * as Redis from '../../../../src/database/redis';
import * as UserActionListener from '../../../../src/listener/UserActionListener';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { disablePublicSharingForDeletedUser, resolvePublicUser, validatePublicUserId } from '../../../../src/modules/dataSharing/dataSharing-utils';

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

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return SYSTEM_USER when userId is null', async () => {
    const result = await resolvePublicUser(mockContext, null);
    expect(result).toBe(SYSTEM_USER);
  });

  it('should return SYSTEM_USER when userId is undefined', async () => {
    const result = await resolvePublicUser(mockContext, undefined);
    expect(result).toBe(SYSTEM_USER);
  });

  it('should throw FunctionalError when userId is an internal system user id', async () => {
    const internalUserId = SYSTEM_USER.id; // '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505'
    await expect(resolvePublicUser(mockContext, internalUserId))
      .rejects.toThrow('Cannot use an internal system user for public sharing');
  });

  it('should throw FunctionalError when user no longer exists in the platform cache', async () => {
    const nonExistentUserId = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);

    await expect(resolvePublicUser(mockContext, nonExistentUserId))
      .rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should return the resolved user when found in the platform cache', async () => {
    const realUserId = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
    const mockUser = { id: realUserId, name: 'Real User' } as any;
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[realUserId, mockUser]]) as any);

    const result = await resolvePublicUser(mockContext, realUserId);
    expect(result).toBe(mockUser);
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
