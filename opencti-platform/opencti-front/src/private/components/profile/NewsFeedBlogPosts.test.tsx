import React from 'react';
import { act, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import NewsFeedBlogPosts from './NewsFeedBlogPosts';

const SETTINGS_ID = 'settings-id-1';
const USER_ID = 'user-1';

const mockCommitMarkAllAsRead = vi.fn();
const mockLoadQuery = vi.fn();
const mockUsePreloadedQuery = vi.fn();
const mockUseQueryLoading = vi.fn();

/** Both the added and the deleted subscription callbacks, in mount order. */
let subscriptionCallbacks: (() => void)[] = [];

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    usePreloadedQuery: (...args: unknown[]) => mockUsePreloadedQuery(...args),
    useMutation: () => [mockCommitMarkAllAsRead, false],
    useSubscription: (config: { onNext: () => void }) => {
      subscriptionCallbacks.push(config.onNext);
    },
  };
});

vi.mock('../../../utils/hooks/useQueryLoading', () => ({
  useQueryLoadingWithLoadQuery: (...args: unknown[]) => mockUseQueryLoading(...args),
}));

vi.mock('./NewsFeedBlogPostCard', () => ({
  default: ({ item }: { item: { id: string; title: string } }) => <div data-testid="blog-post-card">{item.title}</div>,
}));

const buildEdge = (id: string) => ({ node: { id, title: `Title of ${id}`, tags: [], metadata: [], creation_date: '2026-09-11T08:00:00.000Z' } });

const renderBlogPosts = (options?: { settings?: Record<string, unknown>; edges?: unknown[] | null }) => {
  mockUsePreloadedQuery.mockReturnValue({
    myNewsFeeds: options?.edges === null ? null : { edges: options?.edges ?? [buildEdge('post-1'), buildEdge('post-2')] },
  });
  return testRender(<NewsFeedBlogPosts />, {
    userContext: createMockUserContext({
      me: { id: USER_ID },
      settings: options?.settings ?? { id: SETTINGS_ID, platform_xtmhub_url: 'https://hub.filigran.io' },
    }),
  });
};

describe('NewsFeedBlogPosts', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    subscriptionCallbacks = [];
    mockUseQueryLoading.mockReturnValue([{ fake: 'query-ref' }, mockLoadQuery]);
  });

  it('displays a card for each blog post', () => {
    renderBlogPosts();
    expect(screen.getAllByTestId('blog-post-card')).toHaveLength(2);
    expect(screen.getByText('Title of post-1')).toBeInTheDocument();
    expect(screen.getByText('Title of post-2')).toBeInTheDocument();
  });

  it('displays an empty message when there is no blog post', () => {
    renderBlogPosts({ edges: [] });
    expect(screen.queryByTestId('blog-post-card')).not.toBeInTheDocument();
    expect(screen.getByText('No blog post for the moment')).toBeInTheDocument();
  });

  it('displays an empty message when the query returns nothing', () => {
    renderBlogPosts({ edges: null });
    expect(screen.getByText('No blog post for the moment')).toBeInTheDocument();
  });

  it('ignores the empty edges', () => {
    renderBlogPosts({ edges: [null, { node: null }, buildEdge('post-1')] });
    expect(screen.getAllByTestId('blog-post-card')).toHaveLength(1);
  });

  it('displays a loader while the query is not loaded', () => {
    mockUseQueryLoading.mockReturnValue([null, mockLoadQuery]);
    renderBlogPosts();
    expect(screen.queryByTestId('blog-post-card')).not.toBeInTheDocument();
    expect(screen.queryByText('No blog post for the moment')).not.toBeInTheDocument();
  });

  it('asks only the blog posts of the connected user, the most recent first', () => {
    renderBlogPosts();
    const [, variables] = mockUseQueryLoading.mock.calls[0];
    expect(variables).toMatchObject({ orderBy: 'creation_date', orderMode: 'desc' });
    expect(variables.filters.filters).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'entity_type', values: ['NewsFeedItem'] }),
      expect.objectContaining({ key: 'user_id', values: [USER_ID] }),
      expect.objectContaining({ key: 'news_feed_type', values: ['BLOG_POST'], operator: 'eq' }),
    ]));
  });

  it('marks the news feed items as read', () => {
    renderBlogPosts();
    expect(mockCommitMarkAllAsRead).toHaveBeenCalledWith({ variables: {} });
  });

  it('reloads the blog posts when an item is added or deleted', () => {
    renderBlogPosts();
    expect(subscriptionCallbacks).toHaveLength(2);
    act(() => subscriptionCallbacks.forEach((onNext) => onNext()));
    expect(mockLoadQuery).toHaveBeenCalledTimes(2);
    expect(mockLoadQuery).toHaveBeenCalledWith(expect.anything(), { fetchPolicy: 'network-only' });
  });

  describe('See all link', () => {
    it('opens the Filigran blog in a new tab, safely', () => {
      renderBlogPosts();
      const link = screen.getByRole('link', { name: /See all/ });
      expect(link).toHaveAttribute('target', '_blank');
      expect(link.getAttribute('rel')).toContain('noopener');
      const url = new URL(link.getAttribute('href') as string);
      expect(url.origin).toBe('https://filigran.io');
      expect(url.pathname).toBe('/blog');
    });

    it('carries the UTM of the news feed but no platform_id', () => {
      renderBlogPosts();
      const url = new URL(screen.getByRole('link', { name: /See all/ }).getAttribute('href') as string);
      expect(Object.fromEntries(url.searchParams)).toEqual({
        utm_source: SETTINGS_ID,
        utm_medium: 'newsfeed',
        utm_campaign: 'blog_posts',
        utm_content: 'see_all',
      });
    });

    it('opens the staging blog on a staging platform', () => {
      renderBlogPosts({ settings: { id: SETTINGS_ID, platform_xtmhub_url: 'https://hub.staging.filigran.io' } });
      const url = new URL(screen.getByRole('link', { name: /See all/ }).getAttribute('href') as string);
      expect(url.origin).toBe('https://staging.filigran.io');
    });

    it('is still displayed when there is no blog post', () => {
      renderBlogPosts({ edges: [] });
      expect(screen.getByRole('link', { name: /See all/ })).toBeInTheDocument();
    });
  });
});
