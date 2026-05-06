import { describe, it, expect, vi, beforeEach } from 'vitest';
import { addNewsFeed, myNewsFeedsFind, myUnreadNewsFeedsCount } from '../../../src/modules/xtm/hub/news-feed/news-feed-domain';
import { NewsFeedItemType } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';
import type { NewsFeedAddInput } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';

const mockCreateInternalObject = vi.fn();
const mockPageEntitiesConnection = vi.fn();
const mockElCount = vi.fn();
const mockFullEntitiesList = vi.fn();
const mockPatchAttribute = vi.fn();
const mockNotify = vi.fn();

vi.mock('../../../src/domain/internalObject', () => ({
  createInternalObject: (...args: unknown[]) => mockCreateInternalObject(...args),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  pageEntitiesConnection: (...args: unknown[]) => mockPageEntitiesConnection(...args),
  fullEntitiesList: (...args: unknown[]) => mockFullEntitiesList(...args),
}));

vi.mock('../../../src/database/engine', () => ({
  elCount: (...args: unknown[]) => mockElCount(...args),
}));

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: (...args: unknown[]) => mockPatchAttribute(...args),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: (...args: unknown[]) => mockNotify(...args),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    BUS_TOPICS: {
      ...actual.BUS_TOPICS,
      NewsFeedNumber: {
        EDIT_TOPIC: 'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
      },
    },
  };
});

vi.mock('../../../src/utils/filtering/filtering-utils', () => ({
  addFilter: vi.fn((filters: unknown, key: string, value: string) => ({
    mode: 'and',
    filters: [{ key, values: [value] }],
    filterGroups: [],
  })),
}));

const mockContext = {} as any;
const mockUser = { id: 'user-1', name: 'Test User' } as any;

const baseInput: NewsFeedAddInput = {
  title: 'Test news feed item',
  news_feed_type: NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD,
  tags: ['tag1', 'tag2'],
  metadata: [{ key: 'key1', value: 'value1' }],
  creation_date: new Date('2026-01-01T00:00:00.000Z'),
  user_id: mockUser.id,
};

describe('News feed', () => {
  describe('addNewsFeed', () => {
    beforeEach(() => {
      mockCreateInternalObject.mockReset();
      mockElCount.mockReset();
      mockNotify.mockReset();

      // Default mocks for the happy path
      mockElCount.mockResolvedValue(0);
      mockNotify.mockResolvedValue(undefined);
    });

    it('should call createInternalObject with the correct entity type', async () => {
      mockCreateInternalObject.mockResolvedValue({ id: 'new-id', ...baseInput, is_read: false, tags: ['tag1', 'tag2'] });

      await addNewsFeed(mockContext, mockUser, baseInput);

      expect(mockCreateInternalObject).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.objectContaining({ title: baseInput.title }),
        'NewsFeedItem',
      );
    });

    it('should default is_read to false when not provided', async () => {
      mockCreateInternalObject.mockResolvedValue({ user_id: mockUser.id });

      await addNewsFeed(mockContext, mockUser, baseInput);

      expect(mockCreateInternalObject).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.objectContaining({ is_read: false }),
        expect.any(String),
      );
    });

    it('should preserve is_read when explicitly provided as true', async () => {
      mockCreateInternalObject.mockResolvedValue({ user_id: mockUser.id });

      await addNewsFeed(mockContext, mockUser, { ...baseInput, is_read: true });

      expect(mockCreateInternalObject).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.objectContaining({ is_read: true }),
        expect.any(String),
      );
    });

    it('should default tags to an empty array when not provided', async () => {
      mockCreateInternalObject.mockResolvedValue({ user_id: mockUser.id });
      const inputWithoutTags: NewsFeedAddInput = { ...baseInput, tags: undefined as unknown as string[] };

      await addNewsFeed(mockContext, mockUser, inputWithoutTags);

      expect(mockCreateInternalObject).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.objectContaining({ tags: [] }),
        expect.any(String),
      );
    });

    it('should preserve tags when provided', async () => {
      mockCreateInternalObject.mockResolvedValue({ user_id: mockUser.id });

      await addNewsFeed(mockContext, mockUser, baseInput);

      expect(mockCreateInternalObject).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.objectContaining({ tags: ['tag1', 'tag2'] }),
        expect.any(String),
      );
    });

    it('should return the result from createInternalObject', async () => {
      const mockResult = { id: 'created-id', title: 'Test news feed item', user_id: mockUser.id };
      mockCreateInternalObject.mockResolvedValue(mockResult);

      const result = await addNewsFeed(mockContext, mockUser, baseInput);

      expect(result).toBe(mockResult);
    });

    it('should notify with the unread count for the created item user_id', async () => {
      mockCreateInternalObject.mockResolvedValue({ id: 'new-id', user_id: mockUser.id });
      mockElCount.mockResolvedValue(3);

      await addNewsFeed(mockContext, mockUser, baseInput);

      expect(mockNotify).toHaveBeenCalledOnce();
      expect(mockNotify).toHaveBeenCalledWith(
        'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
        { count: 3, user_id: mockUser.id },
        mockUser,
      );
    });

    it('should use the user_id from the created entity (not from the auth user) when notifying', async () => {
      const differentUserId = 'different-user-99';
      mockCreateInternalObject.mockResolvedValue({ id: 'new-id', user_id: differentUserId });
      mockElCount.mockResolvedValue(2);

      await addNewsFeed(mockContext, mockUser, { ...baseInput, user_id: differentUserId });

      expect(mockNotify).toHaveBeenCalledWith(
        'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
        { count: 2, user_id: differentUserId },
        mockUser,
      );
    });
  });

  describe('myNewsFeedsFind', () => {
    beforeEach(() => {
      mockPageEntitiesConnection.mockReset();
    });

    it('should call pageEntitiesConnection with user_id filter added', async () => {
      const opts = { first: 10, filters: null } as any;
      mockPageEntitiesConnection.mockResolvedValue({ edges: [] });

      await myNewsFeedsFind(mockContext, mockUser, opts);

      expect(mockPageEntitiesConnection).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        ['NewsFeedItem'],
        expect.objectContaining({
          filters: expect.objectContaining({
            filters: expect.arrayContaining([
              expect.objectContaining({ key: 'user_id', values: [mockUser.id] }),
            ]),
          }),
        }),
      );
    });

    it('should return the paginated connection from pageEntitiesConnection', async () => {
      const mockConnection = { edges: [{ node: { id: 'item-1' } }], pageInfo: {} };
      mockPageEntitiesConnection.mockResolvedValue(mockConnection);

      const result = await myNewsFeedsFind(mockContext, mockUser, { first: 10 } as any);

      expect(result).toBe(mockConnection);
    });
  });

  describe('myUnreadNewsFeedsCount', () => {
    beforeEach(() => {
      mockElCount.mockReset();
    });

    it('should call elCount with auth user_id and is_read=false filters', async () => {
      mockElCount.mockResolvedValue(5);

      await myUnreadNewsFeedsCount(mockContext, mockUser);

      expect(mockElCount).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.any(String),
        expect.objectContaining({
          filters: expect.objectContaining({
            filters: expect.arrayContaining([
              expect.objectContaining({ key: 'user_id', values: [mockUser.id] }),
              expect.objectContaining({ key: 'is_read', values: [false] }),
            ]),
          }),
        }),
      );
    });

    it('should return the count from elCount', async () => {
      mockElCount.mockResolvedValue(3);

      const result = await myUnreadNewsFeedsCount(mockContext, mockUser);

      expect(result).toBe(3);
    });

    it('should use the provided userId instead of the auth user id when given', async () => {
      const overrideUserId = 'other-user-42';
      mockElCount.mockResolvedValue(4);

      await myUnreadNewsFeedsCount(mockContext, mockUser, overrideUserId);

      expect(mockElCount).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.any(String),
        expect.objectContaining({
          filters: expect.objectContaining({
            filters: expect.arrayContaining([
              expect.objectContaining({ key: 'user_id', values: [overrideUserId] }),
            ]),
          }),
        }),
      );
    });

    it('should return the count from elCount when a userId is provided', async () => {
      mockElCount.mockResolvedValue(7);

      const result = await myUnreadNewsFeedsCount(mockContext, mockUser, 'other-user-42');

      expect(result).toBe(7);
    });
  });
});
