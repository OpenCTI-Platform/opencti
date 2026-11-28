import { beforeEach, describe, expect, it, vi } from 'vitest';
import newsFeedResolvers from '../../../../../../src/modules/xtm/hub/news-feed/news-feed-resolver';

const mockMyUnreadNewsFeedsCounts = vi.fn();

vi.mock('../../../../../../src/modules/xtm/hub/news-feed/news-feed-domain', () => ({
  markAllNewsFeedItemsAsRead: vi.fn(),
  myNewsFeedsFind: vi.fn(),
  myUnreadNewsFeedsCount: vi.fn(),
  myUnreadNewsFeedsCounts: (...args: unknown[]) => mockMyUnreadNewsFeedsCounts(...args),
}));

const mockUser = { id: 'user-1' };
const mockContext = { user: mockUser } as any;

describe('newsFeedResolvers', () => {
  beforeEach(() => {
    mockMyUnreadNewsFeedsCounts.mockReset();
  });

  it('should return the unread counts of every tab for the connected user', async () => {
    const counts = { count: 3, blog_post_count: 1, resource_count: 1, github_release_count: 1, user_id: mockUser.id };
    mockMyUnreadNewsFeedsCounts.mockResolvedValue(counts);

    const result = await (newsFeedResolvers.Query as any).myUnreadNewsFeedsCounts({}, {}, mockContext);

    expect(mockMyUnreadNewsFeedsCounts).toHaveBeenCalledWith(mockContext, mockUser, mockUser.id);
    expect(result).toEqual(counts);
  });
});
