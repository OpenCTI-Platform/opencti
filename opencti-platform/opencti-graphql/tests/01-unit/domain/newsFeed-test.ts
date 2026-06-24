import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  addNewsFeed,
  deleteNewsFeedItemsByExternalId,
  markAllNewsFeedItemsAsRead,
  myNewsFeedsFind,
  myUnreadNewsFeedsCount,
  upsertNewsFeed,
  cleanOldNewsFeedItems,
} from '../../../src/modules/xtm/hub/news-feed/news-feed-domain';
import { NewsFeedItemType } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';
import type { NewsFeedAddInput } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';
import { ALREADY_DELETED_ERROR } from '../../../src/config/errors';

const mockCreateInternalObject = vi.fn();
const mockPageEntitiesConnection = vi.fn();
const mockElCount = vi.fn();
const mockFullEntitiesList = vi.fn();
const mockPatchAttribute = vi.fn();
const mockNotify = vi.fn();
const mockElPaginate = vi.fn();
const mockDeleteElementById = vi.fn();

vi.mock('../../../src/domain/internalObject', () => ({
  createInternalObject: (...args: unknown[]) => mockCreateInternalObject(...args),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  pageEntitiesConnection: (...args: unknown[]) => mockPageEntitiesConnection(...args),
  fullEntitiesList: (...args: unknown[]) => mockFullEntitiesList(...args),
}));

vi.mock('../../../src/database/engine', () => ({
  elCount: (...args: unknown[]) => mockElCount(...args),
  elPaginate: (...args: unknown[]) => mockElPaginate(...args),
}));

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: (...args: unknown[]) => mockPatchAttribute(...args),
  deleteElementById: (...args: unknown[]) => mockDeleteElementById(...args),
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
      NewsFeedItem: {
        ADDED_TOPIC: 'ENTITY_TYPE_NEWS_FEED_ITEM_ADDED_TOPIC',
        EDIT_TOPIC: 'ENTITY_TYPE_NEWS_FEED_ITEM_EDIT_TOPIC',
        DELETE_TOPIC: 'ENTITY_TYPE_NEWS_FEED_ITEM_DELETE_TOPIC',
      },
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
  news_feed_item_id: 'hub-item-base',
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

  describe('markAllNewsFeedItemsAsRead', () => {
    beforeEach(() => {
      mockFullEntitiesList.mockReset();
      mockPatchAttribute.mockReset();
      mockElCount.mockReset();
      mockNotify.mockReset();

      mockPatchAttribute.mockResolvedValue({});
      mockElCount.mockResolvedValue(0);
      mockNotify.mockResolvedValue(undefined);
    });

    it('should query unread items for the current user', async () => {
      mockFullEntitiesList.mockResolvedValue([]);

      const result = await markAllNewsFeedItemsAsRead(mockContext, mockUser);

      expect(mockFullEntitiesList).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        ['NewsFeedItem'],
        expect.objectContaining({
          filters: expect.objectContaining({
            filters: expect.arrayContaining([
              expect.objectContaining({ key: ['user_id'], values: [mockUser.id] }),
              expect.objectContaining({ key: ['is_read'], values: [false] }),
            ]),
          }),
        }),
      );

      expect(result).toBe(true);
    });

    it('should patch each unread item with is_read=true', async () => {
      const unreadItems = [
        { id: 'item-1', is_read: false },
        { id: 'item-2', is_read: false },
        { id: 'item-3', is_read: false },
      ];
      mockFullEntitiesList.mockResolvedValue(unreadItems);

      await markAllNewsFeedItemsAsRead(mockContext, mockUser);

      expect(mockPatchAttribute).toHaveBeenCalledTimes(3);
      for (const item of unreadItems) {
        expect(mockPatchAttribute).toHaveBeenCalledWith(
          mockContext,
          mockUser,
          item.id,
          'NewsFeedItem',
          { is_read: true },
        );
      }
    });

    it('should not call patchAttribute when there are no unread items', async () => {
      mockFullEntitiesList.mockResolvedValue([]);

      await markAllNewsFeedItemsAsRead(mockContext, mockUser);

      expect(mockPatchAttribute).not.toHaveBeenCalled();
    });

    it('should notify with the recomputed unread count after marking all as read', async () => {
      mockFullEntitiesList.mockResolvedValue([{ id: 'item-1', is_read: false }]);
      mockElCount.mockResolvedValue(0);

      await markAllNewsFeedItemsAsRead(mockContext, mockUser);

      expect(mockElCount).toHaveBeenCalledOnce();
      expect(mockNotify).toHaveBeenCalledOnce();
      expect(mockNotify).toHaveBeenCalledWith(
        'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
        { count: 0, user_id: mockUser.id },
        mockUser,
      );
    });

    it('should notify with a non-zero count if new unread items appeared concurrently', async () => {
      mockFullEntitiesList.mockResolvedValue([{ id: 'item-1', is_read: false }]);
      // Simulate a concurrent new unread item arriving after the patches
      mockElCount.mockResolvedValue(1);

      await markAllNewsFeedItemsAsRead(mockContext, mockUser);

      expect(mockElCount).toHaveBeenCalledOnce();
      expect(mockNotify).toHaveBeenCalledOnce();
      expect(mockNotify).toHaveBeenCalledWith(
        'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
        { count: 1, user_id: mockUser.id },
        mockUser,
      );
    });
  });

  describe('cleanOldNewsFeedItems', () => {
    const cutoffDate = new Date('2026-05-01T00:00:00.000Z');

    beforeEach(() => {
      mockElPaginate.mockReset();
      mockDeleteElementById.mockReset();
    });

    it('should call elPaginate with creation_date < cutoff filter', async () => {
      mockElPaginate.mockResolvedValue({ edges: [] });

      await cleanOldNewsFeedItems(mockContext, mockUser, cutoffDate);

      expect(mockElPaginate).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        expect.any(String),
        expect.objectContaining({
          filters: expect.objectContaining({
            filters: expect.arrayContaining([
              expect.objectContaining({
                key: ['creation_date'],
                values: [cutoffDate.toISOString()],
                operator: 'lt',
              }),
            ]),
          }),
          types: ['NewsFeedItem'],
        }),
      );
    });

    it('should delete each returned item and return the count', async () => {
      mockElPaginate
        .mockResolvedValueOnce({
          edges: [
            { node: { internal_id: 'item-1' } },
            { node: { internal_id: 'item-2' } },
            { node: { internal_id: 'item-3' } },
          ],
        });
      mockDeleteElementById.mockResolvedValue(undefined);

      const result = await cleanOldNewsFeedItems(mockContext, mockUser, cutoffDate);

      expect(mockDeleteElementById).toHaveBeenCalledTimes(3);
      expect(mockDeleteElementById).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        'item-1',
        'NewsFeedItem',
      );
      expect(result).toBe(3);
    });

    it('should return 0 and not call delete when no items match', async () => {
      mockElPaginate.mockResolvedValue({ edges: [] });

      const result = await cleanOldNewsFeedItems(mockContext, mockUser, cutoffDate);

      expect(result).toBe(0);
      expect(mockDeleteElementById).not.toHaveBeenCalled();
    });

    it('should swallow ALREADY_DELETED_ERROR without breaking the loop', async () => {
      mockElPaginate.mockResolvedValueOnce({
        edges: [
          { node: { internal_id: 'item-1' } },
          { node: { internal_id: 'item-2' } },
        ],
      });
      const alreadyDeletedError = Object.assign(new Error('Already deleted'), {
        extensions: { code: ALREADY_DELETED_ERROR },
      });
      mockDeleteElementById
        .mockRejectedValueOnce(alreadyDeletedError)
        .mockResolvedValueOnce(undefined);

      const result = await cleanOldNewsFeedItems(mockContext, mockUser, cutoffDate);

      // Le 1er fail silencieusement (n'incrémente pas), le 2e réussit
      expect(result).toBe(1);
      expect(mockDeleteElementById).toHaveBeenCalledTimes(2);
    });
  });

  describe('upsertNewsFeed', () => {
    beforeEach(() => {
      mockFullEntitiesList.mockReset();
      mockCreateInternalObject.mockReset();
      mockPatchAttribute.mockReset();
      mockNotify.mockReset();
      mockElCount.mockReset();
      mockElCount.mockResolvedValue(0);
    });

    it('should update an existing item by news_feed_item_id without changing is_read', async () => {
      mockFullEntitiesList.mockResolvedValueOnce([
        { id: 'existing-id', user_id: mockUser.id, is_read: true },
      ]);
      mockPatchAttribute.mockResolvedValue({
        element: {
          id: 'existing-id',
          user_id: mockUser.id,
          is_read: true,
          title: 'Updated title',
        },
      });

      await upsertNewsFeed(mockContext, mockUser, {
        ...baseInput,
        news_feed_item_id: 'hub-item-1',
        title: 'Updated title',
      });

      expect(mockCreateInternalObject).not.toHaveBeenCalled();
      expect(mockPatchAttribute).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        'existing-id',
        'NewsFeedItem',
        expect.not.objectContaining({ is_read: expect.anything() }),
      );
      expect(mockNotify).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ id: 'existing-id' }),
        mockUser,
      );
    });

    it('should create a new item when no existing item matches by news_feed_item_id', async () => {
      mockFullEntitiesList.mockResolvedValueOnce([]);
      mockCreateInternalObject.mockResolvedValue({ id: 'created-id', user_id: mockUser.id });

      await upsertNewsFeed(mockContext, mockUser, {
        ...baseInput,
        news_feed_item_id: 'hub-item-2',
      });

      expect(mockCreateInternalObject).toHaveBeenCalledOnce();
    });
  });

  describe('deleteNewsFeedItemsByExternalId', () => {
    beforeEach(() => {
      mockFullEntitiesList.mockReset();
      mockDeleteElementById.mockReset();
      mockElCount.mockReset();
      mockNotify.mockReset();
      mockDeleteElementById.mockResolvedValue(undefined);
      mockElCount.mockResolvedValue(0);
    });

    it('should delete all matching items and notify unread counts for impacted users', async () => {
      mockFullEntitiesList.mockResolvedValue([
        { id: 'item-1', user_id: 'user-a' },
        { id: 'item-2', user_id: 'user-b' },
      ]);

      const deletedCount = await deleteNewsFeedItemsByExternalId(mockContext, mockUser, 'hub-item-1');

      expect(deletedCount).toBe(2);
      expect(mockDeleteElementById).toHaveBeenCalledTimes(2);
      expect(mockNotify).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ id: 'item-1' }),
        mockUser,
      );
      expect(mockNotify).toHaveBeenCalledWith(
        'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
        expect.objectContaining({ user_id: 'user-a' }),
        mockUser,
      );
      expect(mockNotify).toHaveBeenCalledWith(
        'ENTITY_TYPE_NEWS_FEED_NUMBER_EDIT_TOPIC',
        expect.objectContaining({ user_id: 'user-b' }),
        mockUser,
      );
    });
  });
});
