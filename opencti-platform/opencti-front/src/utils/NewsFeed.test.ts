import { describe, expect, it } from 'vitest';
import { InsertChartOutlined, InsightsOutlined, LibraryBooksOutlined, NotificationsOutlined } from '@mui/icons-material';
import { getNewsFeedIcon, getNewsFeedLabel, isKnownNewsFeedType } from './NewsFeed';

describe('isKnownNewsFeedType', () => {
  it.each([
    ['RESOURCE_CUSTOM_DASHBOARD', true],
    ['RESOURCE_PLAYBOOK', true],
    ['RESOURCE_CUSTOM_VIEW', true],
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
    ['RESOURCE_SOMETHING_NEW', undefined], // unknown type
    ['', undefined], // empty type
  ])('returns the correct label for %s', (type, expectedLabel) => {
    expect(getNewsFeedLabel(type)).toBe(expectedLabel);
  });
});
