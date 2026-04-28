import { describe, expect, it, vi, beforeEach } from 'vitest';
import { convertNewsFeedItemToStix } from '../../../../../../src/modules/xtm/hub/news-feed/news-feed-converter';
import { NewsFeedItemType } from '../../../../../../src/modules/xtm/hub/news-feed/news-feed-types';
import type { StoreEntityNewsFeedItem } from '../../../../../../src/modules/xtm/hub/news-feed/news-feed-types';
import { STIX_EXT_OCTI } from '../../../../../../src/types/stix-2-1-extensions';

// Mock dependencies to isolate the converter logic
vi.mock('../../../../../../src/database/stix-2-1-converter', () => ({
  buildStixObject: vi.fn(),
}));

vi.mock('../../../../../../src/database/stix-converter-utils', () => ({
  cleanObject: vi.fn((obj) => obj),
}));

import { buildStixObject } from '../../../../../../src/database/stix-2-1-converter';
import { cleanObject } from '../../../../../../src/database/stix-converter-utils';
import type { StixObject } from '../../../../../../src/types/stix-2-1-common';

const buildStixObjectMock = vi.mocked(buildStixObject);
const cleanObjectMock = vi.mocked(cleanObject);

const BASE_STIX_OBJECT: StixObject = {
  id: 'x-opencti-news-feed-item--1234',
  spec_version: '2.1',
  type: NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD,
  extensions: {
    [STIX_EXT_OCTI]: {
      id: 'internal-id-1234',
      type: 'NewsFeedItem',
      extension_type: 'new-sdo',
    },
  },
} as unknown as StixObject;

const buildMockInstance = (overrides: Partial<StoreEntityNewsFeedItem> = {}): StoreEntityNewsFeedItem => ({
  id: 'internal-id-1234',
  standard_id: 'x-opencti-news-feed-item--1234',
  entity_type: 'NewsFeedItem',
  parent_types: [],
  title: 'Test News Item',
  news_feed_type: NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD,
  tags: ['tag1', 'tag2'],
  metadata: [{ key: 'source', value: 'rss' }],
  creation_date: new Date('2024-01-15T10:00:00Z'),
  is_read: false,
  user_id: 'user-abc-123',
  ...overrides,
} as StoreEntityNewsFeedItem);

describe('convertNewsFeedItemToStix', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    buildStixObjectMock.mockReturnValue(BASE_STIX_OBJECT);
    cleanObjectMock.mockImplementation((obj) => obj);
  });

  it('should call buildStixObject with the instance', () => {
    const instance = buildMockInstance();
    convertNewsFeedItemToStix(instance);
    expect(buildStixObjectMock).toHaveBeenCalledOnce();
    expect(buildStixObjectMock).toHaveBeenCalledWith(instance);
  });

  it('should spread the base stix object fields into the result', () => {
    const instance = buildMockInstance();
    const result = convertNewsFeedItemToStix(instance);
    expect(result.id).toBe(BASE_STIX_OBJECT.id);
    expect(result.spec_version).toBe(BASE_STIX_OBJECT.spec_version);
    expect(result.type).toBe(BASE_STIX_OBJECT.type);
  });

  it('should map instance fields onto the stix object', () => {
    const instance = buildMockInstance();
    const result = convertNewsFeedItemToStix(instance);
    expect(result.title).toBe('Test News Item');
    expect(result.news_feed_type).toBe(NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD);
    expect(result.tags).toEqual(['tag1', 'tag2']);
    expect(result.metadata).toEqual([{ key: 'source', value: 'rss' }]);
    expect(result.creation_date).toEqual(new Date('2024-01-15T10:00:00Z'));
    expect(result.is_read).toBe(false);
    expect(result.user_id).toBe('user-abc-123');
  });

  it('should set extension_type to "new-sdo" in the OCTI extension', () => {
    const instance = buildMockInstance();
    const result = convertNewsFeedItemToStix(instance);
    expect(result.extensions[STIX_EXT_OCTI].extension_type).toBe('new-sdo');
  });

  it('should pass the OCTI extension through cleanObject', () => {
    const instance = buildMockInstance();
    convertNewsFeedItemToStix(instance);
    expect(cleanObjectMock).toHaveBeenCalledOnce();
    expect(cleanObjectMock).toHaveBeenCalledWith(
      expect.objectContaining({
        extension_type: 'new-sdo',
      }),
    );
  });

  it('should preserve existing OCTI extension fields and add extension_type', () => {
    const instance = buildMockInstance();
    const result = convertNewsFeedItemToStix(instance);
    const octiExt = result.extensions[STIX_EXT_OCTI];
    expect(octiExt).toMatchObject({
      id: 'internal-id-1234',
      type: 'NewsFeedItem',
      extension_type: 'new-sdo',
    });
  });

  it('should handle an instance with an empty tags array', () => {
    const instance = buildMockInstance({ tags: [] });
    const result = convertNewsFeedItemToStix(instance);
    expect(result.tags).toEqual([]);
  });

  it('should handle an instance with empty metadata array', () => {
    const instance = buildMockInstance({ metadata: [] });
    const result = convertNewsFeedItemToStix(instance);
    expect(result.metadata).toEqual([]);
  });

  it('should handle is_read set to true', () => {
    const instance = buildMockInstance({ is_read: true });
    const result = convertNewsFeedItemToStix(instance);
    expect(result.is_read).toBe(true);
  });

  it('should handle metadata with undefined values', () => {
    const instance = buildMockInstance({ metadata: [{ key: 'optional', value: undefined }] });
    const result = convertNewsFeedItemToStix(instance);
    expect(result.metadata).toEqual([{ key: 'optional', value: undefined }]);
  });
});
