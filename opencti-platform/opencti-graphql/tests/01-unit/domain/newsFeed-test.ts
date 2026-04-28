import { describe, it, expect, vi, beforeEach } from 'vitest';
import { addNewsFeed } from '../../../src/modules/xtm/hub/news-feed/news-feed-domain';
import { NewsFeedItemType } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';
import type { NewsFeedAddInput } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';

const mockCreateInternalObject = vi.fn();

vi.mock('../../../src/domain/internalObject', () => ({
  createInternalObject: (...args: unknown[]) => mockCreateInternalObject(...args),
}));

const mockContext = {} as any;
const mockUser = { id: 'user-1', name: 'Test User' } as any;

const baseInput: NewsFeedAddInput = {
  title: 'Test news feed item',
  news_feed_type: NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD,
  tags: ['tag1', 'tag2'],
  metadata: [{ key: 'key1', value: 'value1' }],
  creation_date: new Date('2026-01-01T00:00:00.000Z'),
  user_id: 'user-1',
};

describe('addNewsFeed', () => {
  beforeEach(() => {
    mockCreateInternalObject.mockReset();
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
    mockCreateInternalObject.mockResolvedValue({});

    await addNewsFeed(mockContext, mockUser, baseInput);

    expect(mockCreateInternalObject).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ is_read: false }),
      expect.any(String),
    );
  });

  it('should preserve is_read when explicitly provided as true', async () => {
    mockCreateInternalObject.mockResolvedValue({});

    await addNewsFeed(mockContext, mockUser, { ...baseInput, is_read: true });

    expect(mockCreateInternalObject).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ is_read: true }),
      expect.any(String),
    );
  });

  it('should default tags to an empty array when not provided', async () => {
    mockCreateInternalObject.mockResolvedValue({});
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
    mockCreateInternalObject.mockResolvedValue({});

    await addNewsFeed(mockContext, mockUser, baseInput);

    expect(mockCreateInternalObject).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      expect.objectContaining({ tags: ['tag1', 'tag2'] }),
      expect.any(String),
    );
  });

  it('should return the result from createInternalObject', async () => {
    const mockResult = { id: 'created-id', title: 'Test news feed item' };
    mockCreateInternalObject.mockResolvedValue(mockResult);

    const result = await addNewsFeed(mockContext, mockUser, baseInput);

    expect(result).toBe(mockResult);
  });
});
