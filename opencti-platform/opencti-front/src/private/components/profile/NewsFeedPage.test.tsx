import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
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
    useSubscription: (config: { onNext: (data: unknown) => void }) => {
      subscriptionOnNext = config.onNext;
    },
  };
});

vi.mock('src/relay/environment', () => ({
  commitMutation: (...args: unknown[]) => mockCommitMutation(...args),
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
  default: () => <div data-testid="news-feed-list" />,
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

const renderPage = (options?: {
  settings?: Record<string, unknown>;
  me?: Record<string, unknown>;
  unreadCount?: number | null;
}) => {
  const settings = options?.settings ?? REGISTERED_SETTINGS;
  mockUseLazyLoadQuery.mockReturnValue({
    myUnreadNotificationsCount: 0,
    myUnreadNewsFeedsCount: options?.unreadCount ?? 0,
    settings,
  });
  return testRender(<NewsFeedPage />, {
    userContext: createMockUserContext({
      settings,
      me: options?.me ?? { id: 'user-1' },
    }),
  });
};

const emitNewsFeedNumber = (count: number | null) => act(() => {
  subscriptionOnNext?.({ newsFeedsNumber: count === null ? null : { count } });
});

const getBadge = () => document.querySelector('.MuiBadge-badge');

describe('NewsFeedPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    subscriptionOnNext = undefined;
    settingsProps = undefined;
  });

  it('renders the page title', () => {
    renderPage();
    expect(screen.getByText('XTM Hub News Feed')).toBeInTheDocument();
  });

  it('renders both tabs', () => {
    renderPage();
    expect(screen.getByRole('tab', { name: /News feed/ })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Settings/ })).toBeInTheDocument();
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
    expect(getBadge()).toHaveClass('MuiBadge-invisible');
  });

  it('hides the badge when the platform is not registered', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_registration_status: 'not_registered' }, unreadCount: 4 });
    expect(getBadge()).toHaveClass('MuiBadge-invisible');
  });

  it('hides the badge when the user unsubscribed from all news feed types', () => {
    renderPage({ me: { id: 'user-1', unsubscribed_news_feed_types: ['*'] }, unreadCount: 4 });
    expect(getBadge()).toHaveClass('MuiBadge-invisible');
  });

  it('prefers the live count over the count of the query', () => {
    renderPage({ unreadCount: 4 });
    emitNewsFeedNumber(9);
    expect(getBadge()).toHaveTextContent('9');
  });

  it('hides the badge when the live count drops to zero', () => {
    renderPage({ unreadCount: 4 });
    emitNewsFeedNumber(0);
    expect(getBadge()).toHaveClass('MuiBadge-invisible');
  });

  it('falls back to the count of the query when the live count is empty', () => {
    renderPage({ unreadCount: 4 });
    emitNewsFeedNumber(null);
    expect(getBadge()).toHaveTextContent('4');
  });

  it('ignores the live count when the platform is not registered', () => {
    renderPage({ settings: { ...REGISTERED_SETTINGS, xtm_hub_registration_status: 'not_registered' }, unreadCount: 0 });
    emitNewsFeedNumber(9);
    expect(getBadge()).toHaveClass('MuiBadge-invisible');
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
