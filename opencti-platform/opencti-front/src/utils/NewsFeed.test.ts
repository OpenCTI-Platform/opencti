import { describe, expect, it } from 'vitest';
import { ArticleOutlined, InsertChartOutlined, InsightsOutlined, IntegrationInstructionsOutlined, LibraryBooksOutlined, NotificationsOutlined } from '@mui/icons-material';
import {
  buildNewsFeedBlogSeeAllUrl,
  getNewsFeedIcon,
  getNewsFeedLabel,
  getNewsFeedMetadataValue,
  isKnownNewsFeedType,
  parseNewsFeedAuthorNames,
  parseNewsFeedReadMinutes,
} from './NewsFeed';

describe('isKnownNewsFeedType', () => {
  it.each([
    ['RESOURCE_CUSTOM_DASHBOARD', true],
    ['RESOURCE_PLAYBOOK', true],
    ['RESOURCE_CUSTOM_VIEW', true],
    ['RESOURCE_INTEGRATION', true],
    ['BLOG_POST', true],
    ['RESOURCE_SOMETHING_NEW', false],
    ['', false],
    ['resource_playbook', false], // case sensitive
    ['toString', false], // inherited Object property
    ['constructor', false], // inherited Object property
    ['hasOwnProperty', false], // inherited Object property
  ])('returns %s for %s', (type, expected) => {
    expect(isKnownNewsFeedType(type)).toBe(expected);
  });
});

describe('getNewsFeedIcon', () => {
  it.each([
    ['RESOURCE_CUSTOM_DASHBOARD', InsertChartOutlined],
    ['RESOURCE_PLAYBOOK', LibraryBooksOutlined],
    ['RESOURCE_CUSTOM_VIEW', InsightsOutlined],
    ['RESOURCE_INTEGRATION', IntegrationInstructionsOutlined],
    ['BLOG_POST', ArticleOutlined],
    ['RESOURCE_SOMETHING_NEW', NotificationsOutlined], // unknown type
    ['', NotificationsOutlined], // empty type
    ['toString', NotificationsOutlined], // inherited Object property
  ])('returns the correct icon for %s', (type, expectedIcon) => {
    expect(getNewsFeedIcon(type)).toBe(expectedIcon);
  });
});

describe('getNewsFeedLabel', () => {
  it.each([
    ['RESOURCE_CUSTOM_DASHBOARD', 'New Custom Dashboard'],
    ['RESOURCE_PLAYBOOK', 'New Playbook'],
    ['RESOURCE_CUSTOM_VIEW', 'New Custom View'],
    ['RESOURCE_INTEGRATION', 'New Integration'],
    ['BLOG_POST', 'Blogpost'],
    ['RESOURCE_SOMETHING_NEW', undefined], // unknown type
    ['', undefined], // empty type
  ])('returns the correct label for %s', (type, expectedLabel) => {
    expect(getNewsFeedLabel(type)).toBe(expectedLabel);
  });
});

describe('getNewsFeedMetadataValue', () => {
  const metadata = [{ key: 'description', value: 'A description' }, { key: 'empty', value: '' }, { key: 'nullable', value: null }];

  it('returns the value of the key', () => {
    expect(getNewsFeedMetadataValue(metadata, 'description')).toBe('A description');
  });

  it.each(['empty', 'nullable', 'unknown'])('returns undefined for the key %s', (key) => {
    expect(getNewsFeedMetadataValue(metadata, key)).toBeUndefined();
  });

  it('returns undefined when there is no metadata', () => {
    expect(getNewsFeedMetadataValue(null, 'description')).toBeUndefined();
    expect(getNewsFeedMetadataValue(undefined, 'description')).toBeUndefined();
  });
});

describe('parseNewsFeedAuthorNames', () => {
  it('returns every author of a JSON array', () => {
    expect(parseNewsFeedAuthorNames('["Romain Guignard","Samuel Hassine"]')).toEqual(['Romain Guignard', 'Samuel Hassine']);
  });

  it('ignores the blank names and the values that are not a name', () => {
    expect(parseNewsFeedAuthorNames('["  Romain Guignard ","",42,null,{"name":"x"}]')).toEqual(['Romain Guignard']);
  });

  it.each([
    ['not a JSON', 'Romain Guignard'],
    ['a truncated JSON', '["Romain'],
    ['a JSON object', '{"name":"Romain Guignard"}'],
    ['a JSON string', '"Romain Guignard"'],
    ['a JSON number', '42'],
    ['an empty string', ''],
  ])('returns no author for %s', (_, raw) => {
    expect(parseNewsFeedAuthorNames(raw)).toEqual([]);
  });

  it('returns no author when there is no value', () => {
    expect(parseNewsFeedAuthorNames(undefined)).toEqual([]);
    expect(parseNewsFeedAuthorNames(null)).toEqual([]);
  });
});

describe('parseNewsFeedReadMinutes', () => {
  it('returns the number of minutes', () => {
    expect(parseNewsFeedReadMinutes('7')).toBe(7);
  });

  it.each(['0', '-3', '7.5', 'seven', '', ' ', '7 min'])('returns undefined for "%s"', (raw) => {
    expect(parseNewsFeedReadMinutes(raw)).toBeUndefined();
  });

  it('returns undefined when there is no value', () => {
    expect(parseNewsFeedReadMinutes(undefined)).toBeUndefined();
    expect(parseNewsFeedReadMinutes(null)).toBeUndefined();
  });
});

describe('buildNewsFeedBlogSeeAllUrl', () => {
  it('targets the Filigran blog with the UTM of the news feed', () => {
    const url = new URL(buildNewsFeedBlogSeeAllUrl('platform-1', 'https://hub.filigran.io'));
    expect(url.origin).toBe('https://filigran.io');
    expect(url.pathname).toBe('/blog');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      utm_source: 'platform-1',
      utm_medium: 'newsfeed',
      utm_campaign: 'blog_posts',
      utm_content: 'see_all',
    });
  });

  it('never carries a platform_id', () => {
    const url = new URL(buildNewsFeedBlogSeeAllUrl('platform-1', 'https://hub.filigran.io'));
    expect(url.searchParams.has('platform_id')).toBe(false);
  });

  it('targets the staging blog when the platform is linked to a staging hub', () => {
    const url = new URL(buildNewsFeedBlogSeeAllUrl('platform-1', 'https://hub.staging.filigran.io/app'));
    expect(url.origin).toBe('https://staging.filigran.io');
    expect(url.pathname).toBe('/blog');
  });

  it.each([undefined, null, '', 'not an url'])('targets the production blog when the hub url is "%s"', (hubUrl) => {
    expect(new URL(buildNewsFeedBlogSeeAllUrl('platform-1', hubUrl)).origin).toBe('https://filigran.io');
  });

  it('does not forge a utm_source when the platform identifier is missing', () => {
    expect(new URL(buildNewsFeedBlogSeeAllUrl(undefined, null)).searchParams.has('utm_source')).toBe(false);
  });
});
