import React, { useState } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import { UserContext } from '../../../utils/hooks/useAuth';
import NewsFeedPage from './NewsFeedPage';

const mockCommitMutation = vi.fn();
const mockUseLazyLoadQuery = vi.fn();

/** Captured so that the news feed number subscription can be triggered from the tests. */
let subscriptionOnNext: ((data: unknown) => void) | undefined;

/** Captured so that the props given to the settings child can be asserted. */
let settingsProps: {
  availableNewsFeedTypes: string[];
  unsubscribedNewsFeedTypes: string[];
  onSubmitField: (name: string, value: string[]) => void;
} | undefined;

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useLazyLoadQuery: (...args: unknown[]) => mockUseLazyLoadQuery(...args),
    useFragment: (_: unknown, ref: unknown) => ref,
  };
});

vi.mock('src/relay/environment', () => ({
  commitMutation: (...args: unknown[]) => mockCommitMutation(...args),
  requestSubscription: (config: { onNext: (data: unknown) => void }) => {
    subscriptionOnNext = config.onNext;
    return { dispose: () => {} };
  },
}));

vi.mock('@common/card/Card', () => ({
  default: ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div>
      <h2>{title}</h2>
      {children}
    </div>
  ),
}));

vi.mock('./NewsFeed', () => ({
  default: ({ markBlogPostsAsRead, markGitHubReleasesAsRead }: { markBlogPostsAsRead?: boolean; markGitHubReleasesAsRead?: boolean }) => (
    <div
      data-testid="news-feed-list"
      data-mark-blog-posts-as-read={String(!!markBlogPostsAsRead)}
      data-mark-github-releases-as-read={String(!!markGitHubReleasesAsRead)}
    />
  ),
}));

vi.mock('./NewsFeedBlogPosts', () => ({
  default: () => <div data-testid="news-feed-blog-posts" />,
}));

vi.mock('./NewsFeedGitHubReleases', () => ({
  default: () => <div data-testid="news-feed-github-releases" />,
}));

vi.mock('./NewsFeedSettings', () => ({
  default: (props: NonNullable<typeof settingsProps>) => {
    settingsProps = props;
    return <div data-testid="news-feed-settings" />;
  },
}));

const REGISTERED_SETTINGS = {
  id: 'settings-id-1',
  xtm_hub_registration_status: 'registered',
  xtm_hub_available_news_feed_types: ['RESOURCE_CUSTOM_DASHBOARD', 'RESOURCE_PLAYBOOK'],
};

const GITHUB_RELEASES_SETTINGS = {
  ...REGISTERED_SETTINGS,
  xtm_hub_available_news_feed_types: ['RESOURCE_CUSTOM_DASHBOARD', 'GITHUB_RELEASE'],
};

const renderPage = (options?: {
  settings?: Record<string, unknown>;
  me?: Record<string, unknown>;
  unreadCount?: number | null;
  unreadBlogPostsCount?: number | null;
  unreadGitHubReleasesCount?: number | null;
}) => {
  const settings = options?.settings ?? REGISTERED_SETTINGS;
  mockUseLazyLoadQuery.mockReturnValue({
    myUnreadNewsFeedsCounts: {
      resource_count: options?.unreadCount ?? 0,
      blog_post_count: options?.unreadBlogPostsCount ?? 0,
      github_release_count: options?.unreadGitHubReleasesCount ?? 0,
    },
    settings,
  });
  return testRender(<NewsFeedPage />, {
    userContext: createMockUserContext({
      settings,
      me: options?.me ?? { id: 'user-1' },
    }),
  });
};

const emitNewsFeedNumber = (
  resourceCount: number | null,
  blogPostCount: number | null = null,
  gitHubReleaseCount: number | null = null,
) => act(() => {
  subscriptionOnNext?.({
    newsFeedsNumber: resourceCount === null && blogPostCount === null && gitHubReleaseCount === null
      ? null
      : { resource_count: resourceCount, blog_post_count: blogPostCount, github_release_count: gitHubReleaseCount },
  });
});

const BLOG_POST_SETTINGS = { ...REGISTERED_SETTINGS, xtm_hub_available_news_feed_types: ['BLOG_POST'] };

const getTabBadge = (tabName: RegExp) => screen.getByRole('tab', { name: tabName }).querySelector('[aria-label$="items"]');
const getBadge = () => getTabBadge(/News feed/);
const getBlogPostsBadge = () => getTabBadge(/Blogpost/);
const getLastReleasesBadge = () => getTabBadge(/Last releases/);

describe('NewsFeedPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    subscriptionOnNext = undefined;
    settingsProps = undefined;
  });

  it('renders the page title', () => {
    renderPage();
    expect(screen.getByRole('heading', { name: 'XTM Hub News Feed' })).toBeInTheDocument();
  });

  it('renders both tabs', () => {
    renderPage();
    expect(screen.getByRole('tab', { name: /News feed/ })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Settings/ })).toBeInTheDocument();
  });

  it('does not render the blogposts tab when the platform does not support the blogposts', () => {
    renderPage();
    expect(screen.queryByRole('tab', { name: /Blogpost/ })).not.toBeInTheDocument();
  });

  it('renders the blogposts tab when the platform supports the blogposts', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_available_news_feed_types: ['BLOG_POST'] } });
    expect(screen.getByRole('tab', { name: /Blogpost/ })).toBeInTheDocument();
  });

  it('makes the news feed mark the blogposts as read when the blogposts tab is not available', () => {
    renderPage();
    expect(screen.getByTestId('news-feed-list')).toHaveAttribute('data-mark-blog-posts-as-read', 'true');
  });

  it('keeps the blogposts unread on the news feed when the blogposts tab is available', () => {
    renderPage({ settings: BLOG_POST_SETTINGS });
    expect(screen.getByTestId('news-feed-list')).toHaveAttribute('data-mark-blog-posts-as-read', 'false');
  });

  it('makes the news feed mark the GitHub releases as read when the last releases tab is not available', () => {
    renderPage();
    expect(screen.getByTestId('news-feed-list')).toHaveAttribute('data-mark-github-releases-as-read', 'true');
  });

  it('keeps the GitHub releases unread on the news feed when the last releases tab is available', () => {
    renderPage({ settings: GITHUB_RELEASES_SETTINGS });
    expect(screen.getByTestId('news-feed-list')).toHaveAttribute('data-mark-github-releases-as-read', 'false');
  });

  it('displays the blogposts when the blogposts tab is selected', async () => {
    const { user } = renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_available_news_feed_types: ['BLOG_POST'] } });
    await user.click(screen.getByRole('tab', { name: /Blogpost/ }));
    expect(screen.getByTestId('news-feed-blog-posts')).toBeInTheDocument();
    expect(screen.queryByTestId('news-feed-list')).not.toBeInTheDocument();
  });

  it('displays the news feed list by default', () => {
    renderPage();
    expect(screen.getByTestId('news-feed-list')).toBeInTheDocument();
    expect(screen.queryByTestId('news-feed-settings')).not.toBeInTheDocument();
  });

  it('displays the settings when the settings tab is selected', async () => {
    const { user } = renderPage();
    await user.click(screen.getByRole('tab', { name: /Settings/ }));
    expect(screen.getByTestId('news-feed-settings')).toBeInTheDocument();
    expect(screen.queryByTestId('news-feed-list')).not.toBeInTheDocument();
  });

  it('hides the Last releases tab when the platform cannot receive GitHub releases', () => {
    renderPage();
    expect(screen.queryByRole('tab', { name: /Last releases/ })).not.toBeInTheDocument();
  });

  it('hides the Last releases tab when the platform has no available type', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_available_news_feed_types: null } });
    expect(screen.queryByRole('tab', { name: /Last releases/ })).not.toBeInTheDocument();
  });

  it('displays the Last releases tab when the platform can receive GitHub releases', () => {
    renderPage({ settings: GITHUB_RELEASES_SETTINGS });
    expect(screen.getByRole('tab', { name: /Last releases/ })).toBeInTheDocument();
  });

  it('displays the GitHub releases when the Last releases tab is selected', async () => {
    const { user } = renderPage({ settings: GITHUB_RELEASES_SETTINGS });
    await user.click(screen.getByRole('tab', { name: /Last releases/ }));
    expect(screen.getByTestId('news-feed-github-releases')).toBeInTheDocument();
    expect(screen.queryByTestId('news-feed-list')).not.toBeInTheDocument();
    expect(screen.queryByTestId('news-feed-settings')).not.toBeInTheDocument();
  });

  it('gives the available news feed types of the platform to the settings', async () => {
    const { user } = renderPage();
    await user.click(screen.getByRole('tab', { name: /Settings/ }));
    expect(settingsProps?.availableNewsFeedTypes).toEqual(['RESOURCE_CUSTOM_DASHBOARD', 'RESOURCE_PLAYBOOK']);
  });

  it('gives the unsubscribed news feed types of the user to the settings', async () => {
    const { user } = renderPage({ me: { id: 'user-1', unsubscribed_news_feed_types: ['RESOURCE_PLAYBOOK'] } });
    await user.click(screen.getByRole('tab', { name: /Settings/ }));
    expect(settingsProps?.unsubscribedNewsFeedTypes).toEqual(['RESOURCE_PLAYBOOK']);
  });

  it('gives an empty list to the settings when the platform has no available type', async () => {
    const { user } = renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_available_news_feed_types: null } });
    await user.click(screen.getByRole('tab', { name: /Settings/ }));
    expect(settingsProps?.availableNewsFeedTypes).toEqual([]);
    expect(settingsProps?.unsubscribedNewsFeedTypes).toEqual([]);
  });

  it('displays the unread count of the query in the badge', () => {
    renderPage({ unreadCount: 4 });
    expect(getBadge()).toHaveTextContent('4');
  });

  it('caps the displayed unread count to 99+', () => {
    renderPage({ unreadCount: 150 });
    expect(getBadge()).toHaveTextContent('99+');
  });

  it('hides the badge when there is no unread news feed item', () => {
    renderPage({ unreadCount: 0 });
    expect(getBadge()).not.toBeInTheDocument();
  });

  it('hides the badge when the platform is not registered', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_registration_status: 'not_registered' }, unreadCount: 4 });
    expect(getBadge()).not.toBeInTheDocument();
  });

  it('displays the unread blogposts count on the blogposts tab only', () => {
    renderPage({ settings: BLOG_POST_SETTINGS, unreadCount: 2, unreadBlogPostsCount: 5 });
    expect(getBlogPostsBadge()).toHaveTextContent('5');
    expect(getBadge()).toHaveTextContent('2');
  });

  it('does not count the blogposts on the news feed tab', () => {
    renderPage({ settings: BLOG_POST_SETTINGS, unreadCount: 0, unreadBlogPostsCount: 5 });
    expect(getBadge()).not.toBeInTheDocument();
    expect(getBlogPostsBadge()).toHaveTextContent('5');
  });

  it('hides the blogposts badge when there is no unread blogpost', () => {
    renderPage({ settings: BLOG_POST_SETTINGS, unreadCount: 3, unreadBlogPostsCount: 0 });
    expect(getBlogPostsBadge()).not.toBeInTheDocument();
  });

  it('displays the unread GitHub releases count on the last releases tab only', () => {
    renderPage({ settings: GITHUB_RELEASES_SETTINGS, unreadCount: 2, unreadGitHubReleasesCount: 3 });
    expect(getLastReleasesBadge()).toHaveTextContent('3');
    expect(getBadge()).toHaveTextContent('2');
  });

  it('hides the last releases badge when there is no unread GitHub release', () => {
    renderPage({ settings: GITHUB_RELEASES_SETTINGS, unreadCount: 2, unreadGitHubReleasesCount: 0 });
    expect(getLastReleasesBadge()).not.toBeInTheDocument();
  });

  it('updates the last releases badge with its own live count', () => {
    renderPage({ settings: GITHUB_RELEASES_SETTINGS, unreadCount: 2, unreadGitHubReleasesCount: 0 });
    emitNewsFeedNumber(2, 0, 1);
    expect(getLastReleasesBadge()).toHaveTextContent('1');
    expect(getBadge()).toHaveTextContent('2');
  });

  it('updates each badge with its own live count', () => {
    renderPage({ settings: BLOG_POST_SETTINGS, unreadCount: 2, unreadBlogPostsCount: 5 });
    emitNewsFeedNumber(7, 0);
    expect(getBadge()).toHaveTextContent('7');
    expect(getBlogPostsBadge()).not.toBeInTheDocument();
  });

  it('hides the disconnected banner when the platform is registered', () => {
    renderPage();
    expect(screen.queryByText('XTM Hub is disconnected')).not.toBeInTheDocument();
  });

  it('displays the disconnected banner when the platform is not registered', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_registration_status: 'not_registered' } });
    expect(screen.getByText('XTM Hub is disconnected')).toBeInTheDocument();
  });

  it('displays the unreachable banner when XTM Hub backend is not reachable', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_backend_is_reachable: false } });
    expect(screen.getByText('XTM Hub is disconnected')).toBeInTheDocument();
    expect(screen.getByText("XTM Hub is unreachable and connection can't be established")).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Connect product to XTM Hub' })).not.toBeInTheDocument();
  });

  it('hides the badge when the user unsubscribed from all news feed types', () => {
    renderPage({ me: { id: 'user-1', unsubscribed_news_feed_types: ['*'] }, unreadCount: 4 });
    expect(getBadge()).not.toBeInTheDocument();
  });

  it('prefers the live count over the count of the query', () => {
    renderPage({ unreadCount: 4 });
    emitNewsFeedNumber(9);
    expect(getBadge()).toHaveTextContent('9');
  });

  it('hides the badge when the live count drops to zero', () => {
    renderPage({ unreadCount: 4 });
    emitNewsFeedNumber(0);
    expect(getBadge()).not.toBeInTheDocument();
  });

  it('falls back to the count of the query when the live count is empty', () => {
    renderPage({ unreadCount: 4 });
    emitNewsFeedNumber(null);
    expect(getBadge()).toHaveTextContent('4');
  });

  it('does not reuse the stale live counts when the news feed is enabled again', () => {
    let setUnsubscribed: (value: boolean) => void = () => {};
    mockUseLazyLoadQuery.mockReturnValue({
      myUnreadNewsFeedsCounts: { resource_count: 4, blog_post_count: 2, github_release_count: 0 },
      settings: BLOG_POST_SETTINGS,
    });
    const Harness = () => {
      const [unsubscribed, setValue] = useState(false);
      setUnsubscribed = setValue;
      return (
        <UserContext.Provider
          value={createMockUserContext({
            settings: BLOG_POST_SETTINGS,
            me: { id: 'user-1', unsubscribed_news_feed_types: unsubscribed ? ['*'] : [] },
          })}
        >
          <NewsFeedPage />
        </UserContext.Provider>
      );
    };
    testRender(<Harness />);
    emitNewsFeedNumber(9, 8);
    expect(getBadge()).toHaveTextContent('9');
    expect(getBlogPostsBadge()).toHaveTextContent('8');

    act(() => setUnsubscribed(true));
    act(() => setUnsubscribed(false));
    expect(getBadge()).toHaveTextContent('4');
    expect(getBlogPostsBadge()).toHaveTextContent('2');
  });

  it('ignores the live count when the platform is not registered', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_registration_status: 'not_registered' }, unreadCount: 0 });
    emitNewsFeedNumber(9);
    expect(getBadge()).not.toBeInTheDocument();
  });

  it('updates the unsubscribed news feed types of the user when the settings are submitted', async () => {
    const { user } = renderPage();
    await user.click(screen.getByRole('tab', { name: /Settings/ }));
    act(() => settingsProps?.onSubmitField('unsubscribed_news_feed_types', ['RESOURCE_PLAYBOOK']));
    expect(mockCommitMutation).toHaveBeenCalledWith(expect.objectContaining({
      variables: { input: [{ key: 'unsubscribed_news_feed_types', value: ['RESOURCE_PLAYBOOK'] }] },
    }));
  });
});
