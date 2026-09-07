import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import NewsFeedToastManager from './NewsFeedToastManager';
import { NewsFeedToastData } from './NewsFeedToastItem';

const HUB_URL = 'https://hub.filigran.io';

interface CapturedSubscription {
  subscription: unknown;
  onNext: (data: unknown) => void;
  dispose: ReturnType<typeof vi.fn>;
}

const capturedSubscriptions: CapturedSubscription[] = [];

vi.mock('../../../relay/environment', () => ({
  requestSubscription: ({ subscription, onNext }: { subscription: unknown; onNext: (data: unknown) => void }) => {
    const dispose = vi.fn();
    capturedSubscriptions.push({ subscription, onNext, dispose });
    return { dispose };
  },
}));

vi.mock('./NewsFeedToastItem', () => ({
  __esModule: true,
  NEWS_FEED_TOAST_WIDTH: 450,
  default: ({ item }: { item: NewsFeedToastData }) => (
    <div data-testid="toast-item">{item.title}</div>
  ),
}));

/**
 * Subscriptions are registered in mount order: news feed item added, then deleted.
 * The manager only registers them when it is enabled.
 */
const emitAdded = (item: Partial<NewsFeedToastData> & { id: string }) => act(() => {
  capturedSubscriptions[0].onNext({
    newsFeedItemAdded: {
      title: `Title of ${item.id}`,
      news_feed_type: 'RESOURCE_CUSTOM_DASHBOARD',
      metadata: [],
      ...item,
    },
  });
});

const emitDeleted = (id: string | null) => act(() => {
  capturedSubscriptions[1].onNext({ newsFeedItemDeleted: id });
});

const ENABLED_SETTINGS = {
  id: 'settings-id-1',
  xtm_hub_registration_status: 'registered',
  platform_xtmhub_url: HUB_URL,
};

const renderManager = (options?: { settings?: Record<string, unknown>; me?: Record<string, unknown> }) => testRender(
  <NewsFeedToastManager />,
  {
    userContext: createMockUserContext({
      settings: options?.settings ?? ENABLED_SETTINGS,
      me: options?.me ?? { id: 'user-1' },
    }),
  },
);

describe('NewsFeedToastManager', () => {
  beforeEach(() => {
    capturedSubscriptions.length = 0;
  });

  it('renders nothing when the platform is not registered', () => {
    const { container } = renderManager({ settings: { ...ENABLED_SETTINGS, xtm_hub_registration_status: 'not_registered' } });
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing when the user unsubscribed from all news feed types', () => {
    const { container } = renderManager({ me: { id: 'user-1', unsubscribed_news_feed_types: ['*'] } });
    expect(container).toBeEmptyDOMElement();
  });

  it('does not subscribe when it is disabled', () => {
    renderManager({ settings: { ...ENABLED_SETTINGS, xtm_hub_registration_status: 'not_registered' } });
    expect(capturedSubscriptions).toHaveLength(0);
  });

  it('subscribes to added and deleted news feed items when it is enabled', () => {
    renderManager();
    expect(capturedSubscriptions).toHaveLength(2);
  });

  it('renders nothing while no news feed item has been received', () => {
    const { container } = renderManager();
    expect(container).toBeEmptyDOMElement();
  });

  it('renders a toast when a news feed item is received', () => {
    renderManager();
    emitAdded({ id: 'item-1', title: 'Brand new dashboard' });
    expect(screen.getByText('Brand new dashboard')).toBeInTheDocument();
  });

  it('ignores a payload without a news feed item', () => {
    const { container } = renderManager();
    act(() => capturedSubscriptions[0].onNext({}));
    expect(container).toBeEmptyDOMElement();
  });

  it('deduplicates news feed items sharing the same id', () => {
    renderManager();
    emitAdded({ id: 'item-1' });
    emitAdded({ id: 'item-1' });
    expect(screen.getAllByTestId('toast-item')).toHaveLength(1);
  });

  it('removes the toast of a deleted news feed item', () => {
    renderManager();
    emitAdded({ id: 'item-1' });
    emitAdded({ id: 'item-2' });
    emitDeleted('item-1');
    expect(screen.getAllByTestId('toast-item')).toHaveLength(1);
    expect(screen.getByText('Title of item-2')).toBeInTheDocument();
  });

  it('keeps the toasts when the deleted id is unknown', () => {
    renderManager();
    emitAdded({ id: 'item-1' });
    emitDeleted('item-unknown');
    expect(screen.getAllByTestId('toast-item')).toHaveLength(1);
  });

  it('keeps the toasts when the deleted id is null', () => {
    renderManager();
    emitAdded({ id: 'item-1' });
    emitDeleted(null);
    expect(screen.getAllByTestId('toast-item')).toHaveLength(1);
  });

  it('displays at most five toasts', () => {
    renderManager();
    for (let i = 0; i < 7; i += 1) {
      emitAdded({ id: `item-${i}` });
    }
    expect(screen.getAllByTestId('toast-item')).toHaveLength(5);
  });

  it('displays the number of hidden news feed items', () => {
    renderManager();
    for (let i = 0; i < 7; i += 1) {
      emitAdded({ id: `item-${i}` });
    }
    expect(screen.getByText('(+2) Click to view all the new resources on the Hub')).toBeInTheDocument();
  });

  it('links the overflow banner to the hub application', () => {
    renderManager();
    for (let i = 0; i < 7; i += 1) {
      emitAdded({ id: `item-${i}` });
    }
    expect(screen.getByRole('link', { name: 'View all on XTM Hub' })).toHaveAttribute('href', `${HUB_URL}/app`);
  });

  it('does not display the overflow banner when the hub url is not configured', () => {
    renderManager({ settings: { id: 'settings-id-1', xtm_hub_registration_status: 'registered' } });
    for (let i = 0; i < 7; i += 1) {
      emitAdded({ id: `item-${i}` });
    }
    expect(screen.queryByRole('link', { name: 'View all on XTM Hub' })).not.toBeInTheDocument();
  });

  it('does not display the overflow banner when all the toasts are visible', () => {
    renderManager();
    emitAdded({ id: 'item-1' });
    expect(screen.queryByRole('link', { name: 'View all on XTM Hub' })).not.toBeInTheDocument();
  });

  it('removes every toast when dismissing all of them', async () => {
    const { user, container } = renderManager();
    emitAdded({ id: 'item-1' });
    emitAdded({ id: 'item-2' });
    await user.click(screen.getByRole('button', { name: 'Dismiss all' }));
    expect(container).toBeEmptyDOMElement();
  });

  it('disposes the subscriptions on unmount', () => {
    const { unmount } = renderManager();
    unmount();
    expect(capturedSubscriptions[0].dispose).toHaveBeenCalled();
    expect(capturedSubscriptions[1].dispose).toHaveBeenCalled();
  });
});
