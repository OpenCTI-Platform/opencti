import React from 'react';
import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import NewsFeedToastItem, { NewsFeedToastData } from './NewsFeedToastItem';

const HUB_URL = 'https://hub.filigran.io';
const SETTINGS_ID = 'settings-id-1';

const buildItem = (overrides: Partial<NewsFeedToastData> = {}): NewsFeedToastData => ({
  id: 'news-feed-item-1',
  title: 'Brand new dashboard',
  news_feed_type: 'RESOURCE_CUSTOM_DASHBOARD',
  metadata: [{ key: 'url_path', value: '/dashboards/1' }],
  ...overrides,
});

const UNSUPPORTED_TYPE_MESSAGE = 'A new content type is available but cannot be displayed in this notification due to your OpenCTI version, please upgrade';

const renderItem = (item: NewsFeedToastData, settings?: Record<string, unknown>) => testRender(
  <NewsFeedToastItem item={item} />,
  {
    userContext: createMockUserContext({
      settings: settings ?? { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL },
    }),
  },
);

describe('NewsFeedToastItem', () => {
  it('renders the title of the item', () => {
    renderItem(buildItem());
    expect(screen.getByText('Brand new dashboard')).toBeInTheDocument();
  });

  it('renders the label of a known news feed type', () => {
    renderItem(buildItem());
    expect(screen.getByText('New Custom Dashboard')).toBeInTheDocument();
  });

  it('does not render any type label for an unknown news feed type', () => {
    renderItem(buildItem({ news_feed_type: 'RESOURCE_SOMETHING_NEW' }));
    expect(screen.queryByText('New Custom Dashboard')).not.toBeInTheDocument();
    expect(screen.queryByText('New Playbook')).not.toBeInTheDocument();
  });

  it('does not warn about the version for a known news feed type', () => {
    renderItem(buildItem());
    expect(screen.queryByText(UNSUPPORTED_TYPE_MESSAGE)).not.toBeInTheDocument();
  });

  it('warns about the version for an unknown news feed type', () => {
    renderItem(buildItem({ news_feed_type: 'RESOURCE_SOMETHING_NEW' }));
    expect(screen.getByText(UNSUPPORTED_TYPE_MESSAGE)).toBeInTheDocument();
  });

  it('renders a link to the resource on the hub', () => {
    renderItem(buildItem());
    const link = screen.getByRole('link', { name: 'Open in XTM Hub' });
    const url = new URL(link.getAttribute('href') as string);
    expect(url.origin).toBe(HUB_URL);
    expect(url.pathname).toBe('/dashboards/1');
    expect(url.searchParams.get('platform_id')).toBe(SETTINGS_ID);
  });

  it('opens the hub link in a new safe tab', () => {
    renderItem(buildItem());
    const link = screen.getByRole('link', { name: 'Open in XTM Hub' });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('does not render a link when the item has no url path metadata', () => {
    renderItem(buildItem({ metadata: [{ key: 'other', value: 'value' }] }));
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('does not render a link when the item has no metadata', () => {
    renderItem(buildItem({ metadata: [] }));
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('does not render a link when the hub url is not configured', () => {
    renderItem(buildItem(), { id: SETTINGS_ID });
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('does not render a link when the url path is absolute', () => {
    renderItem(buildItem({ metadata: [{ key: 'url_path', value: 'https://evil.example/steal' }] }));
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});
