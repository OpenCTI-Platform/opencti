import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import NewsFeedBlogPostCard, { NewsFeedBlogPostData } from './NewsFeedBlogPostCard';

const HUB_URL = 'https://hub.filigran.io';
const SETTINGS_ID = 'settings-id-1';
const TITLE = 'OpenCTI and Google SecOps SOAR: Threat Intel Flows Both Ways';

const FULL_METADATA = [
  { key: 'url_path', value: '/redirect/blog-post/1' },
  { key: 'description', value: 'How the two platforms exchange threat intelligence.' },
  { key: 'image_url', value: 'https://filigran.io/images/cover.png' },
  { key: 'image_alt', value: 'Cover of the article' },
  { key: 'author_names', value: '["Romain Guignard"]' },
  { key: 'read_minutes', value: '7' },
];

const buildItem = (overrides: Partial<NewsFeedBlogPostData> = {}): NewsFeedBlogPostData => ({
  id: 'news-feed-item-1',
  title: TITLE,
  tags: ['Threat Intelligence', 'Partnership'],
  metadata: FULL_METADATA,
  creation_date: '2026-09-11T08:00:00.000Z',
  ...overrides,
});

/** The full set of metadata, but for the given keys. */
const withoutMetadata = (...keys: string[]) => FULL_METADATA.filter(({ key }) => !keys.includes(key));

const renderCard = (item: NewsFeedBlogPostData, settings?: Record<string, unknown>) => testRender(
  <NewsFeedBlogPostCard item={item} />,
  {
    userContext: createMockUserContext({
      settings: settings ?? { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL },
    }),
  },
);

describe('NewsFeedBlogPostCard', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('with every field', () => {
    it('renders the title, the description, the authors and the read time', () => {
      renderCard(buildItem());
      expect(screen.getByText(TITLE)).toBeInTheDocument();
      expect(screen.getByText('How the two platforms exchange threat intelligence.')).toBeInTheDocument();
      expect(screen.getByText('Romain Guignard')).toBeInTheDocument();
      expect(screen.getByText('7 min read')).toBeInTheDocument();
    });

    it('renders a long title entirely, without truncation', () => {
      const longTitle = 'A very long blog post title '.repeat(12).trim();
      renderCard(buildItem({ title: longTitle }));
      expect(screen.getByText(longTitle)).toBeInTheDocument();
    });

    it('renders the tags', () => {
      renderCard(buildItem());
      expect(screen.getByText('Threat Intelligence')).toBeInTheDocument();
      expect(screen.getByText('Partnership')).toBeInTheDocument();
    });

    it('renders the publication date', () => {
      renderCard(buildItem());
      expect(document.querySelector('time')).toHaveAttribute('datetime', '2026-09-11T08:00:00.000Z');
      expect(document.querySelector('time')).not.toBeEmptyDOMElement();
    });

    it('renders the image with its alternative text', () => {
      renderCard(buildItem());
      const image = screen.getByRole('img', { name: 'Cover of the article' });
      expect(image).toHaveAttribute('src', 'https://filigran.io/images/cover.png');
    });

    it('displays every author of the article', () => {
      renderCard(buildItem({
        metadata: [...withoutMetadata('author_names'), { key: 'author_names', value: '["Romain Guignard","Samuel Hassine"]' }],
      }));
      expect(screen.getByText('Romain Guignard, Samuel Hassine')).toBeInTheDocument();
    });
  });

  describe('opening the article', () => {
    it('opens the hub redirect in a new tab without giving access to the platform', async () => {
      const windowOpen = vi.spyOn(window, 'open').mockReturnValue(null);
      const { user } = renderCard(buildItem());
      await user.click(screen.getByText(TITLE));
      expect(windowOpen).toHaveBeenCalledTimes(1);
      const [href, target, features] = windowOpen.mock.calls[0];
      const url = new URL(href as string);
      expect(url.origin).toBe(HUB_URL);
      expect(url.pathname).toBe('/redirect/blog-post/1');
      expect(url.searchParams.get('platform_id')).toBe(SETTINGS_ID);
      expect(target).toBe('_blank');
      expect(features).toBe('noopener,noreferrer');
    });

    it.each([
      ['has no url path', withoutMetadata('url_path')],
      ['has an absolute url path', [...withoutMetadata('url_path'), { key: 'url_path', value: 'https://evil.example/steal' }]],
    ])('does not open anything when the article %s', async (_, metadata) => {
      const windowOpen = vi.spyOn(window, 'open').mockReturnValue(null);
      const { user } = renderCard(buildItem({ metadata }));
      await user.click(screen.getByText(TITLE));
      expect(windowOpen).not.toHaveBeenCalled();
    });

    it('does not open anything when the hub url is not configured', async () => {
      const windowOpen = vi.spyOn(window, 'open').mockReturnValue(null);
      const { user } = renderCard(buildItem(), { id: SETTINGS_ID });
      await user.click(screen.getByText(TITLE));
      expect(windowOpen).not.toHaveBeenCalled();
    });
  });

  describe('with missing optional fields', () => {
    it('renders no image when there is no image url', () => {
      renderCard(buildItem({ metadata: withoutMetadata('image_url', 'image_alt') }));
      expect(screen.queryByRole('img')).not.toBeInTheDocument();
      expect(document.querySelector('img')).not.toBeInTheDocument();
      expect(screen.getByText(TITLE)).toBeInTheDocument();
    });

    it.each([
      'javascript:alert(1)',
      'data:image/png;base64,AAAA',
      'not an url',
    ])('does not render an image whose url is %s', (value) => {
      renderCard(buildItem({ metadata: [...withoutMetadata('image_url'), { key: 'image_url', value }] }));
      expect(document.querySelector('img')).not.toBeInTheDocument();
    });

    it('hides the image when it cannot be loaded', () => {
      renderCard(buildItem());
      fireEvent.error(screen.getByRole('img', { name: 'Cover of the article' }));
      expect(document.querySelector('img')).not.toBeInTheDocument();
    });

    it('renders no description when there is none', () => {
      renderCard(buildItem({ metadata: withoutMetadata('description') }));
      expect(screen.queryByText('How the two platforms exchange threat intelligence.')).not.toBeInTheDocument();
      expect(screen.getByText(TITLE)).toBeInTheDocument();
    });

    it('renders only the read time when there is no author', () => {
      renderCard(buildItem({ metadata: withoutMetadata('author_names') }));
      expect(screen.getByText('7 min read')).toBeInTheDocument();
      expect(screen.queryByText('Romain Guignard')).not.toBeInTheDocument();
    });

    it('renders only the authors when there is no read time', () => {
      renderCard(buildItem({ metadata: withoutMetadata('read_minutes') }));
      expect(screen.getByText('Romain Guignard')).toBeInTheDocument();
      expect(screen.queryByText(/min read/)).not.toBeInTheDocument();
    });

    it('renders neither authors nor read time when there are none', () => {
      renderCard(buildItem({ metadata: withoutMetadata('author_names', 'read_minutes') }));
      expect(screen.queryByText(/min read/)).not.toBeInTheDocument();
      expect(screen.queryByText('Romain Guignard')).not.toBeInTheDocument();
    });

    it('renders no tag when there is none', () => {
      renderCard(buildItem({ tags: [] }));
      expect(screen.queryByText('Threat Intelligence')).not.toBeInTheDocument();
      expect(screen.getByText(TITLE)).toBeInTheDocument();
    });

    it('ignores the empty tags', () => {
      renderCard(buildItem({ tags: ['', null, 'Partnership'] }));
      expect(screen.getByText('Partnership')).toBeInTheDocument();
    });

    it('renders only the title when the item has no metadata at all', () => {
      renderCard(buildItem({ tags: [], metadata: [] }));
      expect(screen.getByText(TITLE)).toBeInTheDocument();
      expect(document.querySelector('img')).not.toBeInTheDocument();
    });
  });

  describe('with malformed optional fields', () => {
    it.each([
      ['an invalid JSON', 'Romain Guignard'],
      ['a JSON object', '{"name":"Romain Guignard"}'],
      ['a JSON string', '"Romain Guignard"'],
    ])('does not crash and shows no author when author_names is %s', (_, value) => {
      renderCard(buildItem({ metadata: [...withoutMetadata('author_names'), { key: 'author_names', value }] }));
      expect(screen.getByText(TITLE)).toBeInTheDocument();
      expect(screen.queryByText('Romain Guignard')).not.toBeInTheDocument();
    });

    it.each(['seven', '0', '-1', '7.5'])('shows no read time when read_minutes is "%s"', (value) => {
      renderCard(buildItem({ metadata: [...withoutMetadata('read_minutes'), { key: 'read_minutes', value }] }));
      expect(screen.getByText(TITLE)).toBeInTheDocument();
      expect(screen.queryByText(/min read/)).not.toBeInTheDocument();
    });
  });
});
