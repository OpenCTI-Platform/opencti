import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Middleware from '../../../../src/database/middleware';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import { createFeed, editFeed } from '../../../../src/modules/dataSharing/feed-domain';
import { createStreamCollection, streamCollectionEditField } from '../../../../src/modules/dataSharing/streamCollection-domain';
import { createTaxiiCollection, taxiiCollectionEditField } from '../../../../src/modules/dataSharing/taxiiCollection-domain';
import type { FeedAddInput, StreamCollectionAddInput, TaxiiCollectionAddInput } from '../../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/database/cache');

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  updateAttribute: vi.fn().mockResolvedValue({ element: { name: 'test', id: 'mock-id' } }),
  stixLoadByIds: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', () => ({
  pageEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
  fullEntitiesList: vi.fn(),
}));

vi.mock('../../../../src/database/engine', () => ({
  elPaginate: vi.fn(),
  elReplace: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn(),
  setEditContext: vi.fn(),
  delEditContext: vi.fn(),
}));

vi.mock('../../../../src/database/redis-stream', () => ({
  getStreamProductionRate: vi.fn(),
}));

vi.mock('../../../../src/database/stream/stream-handler', () => ({
  fetchStreamInfo: vi.fn(),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/graphql/streamConsumerRegistry', () => ({
  getConsumersForCollection: vi.fn(),
  getLocalConsumerMetrics: vi.fn(),
}));

vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    logApp: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
  };
});

const mockContext = { source: 'testing' } as any;
const mockUser = SYSTEM_USER;

const VALID_USER_ID = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
const mockRealUser = { id: VALID_USER_ID, name: 'Real User' } as any;
const NONEXISTENT_USER_ID = 'ffffffff-ffff-4fff-ffff-ffffffffffff';

beforeEach(() => {
  vi.clearAllMocks();
});

// ---------- Feed ----------

describe('createFeed domain validation', () => {
  it('should throw when feed_public is true without feed_public_user_id', async () => {
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(createFeed(mockContext, mockUser, input)).rejects.toThrow('A user must be configured when the feed is public');
  });

  it('should throw when feed_public_user_id refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_public_user_id: NONEXISTENT_USER_ID, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(createFeed(mockContext, mockUser, input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should call createEntity when feed_public_user_id is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.createEntity).mockResolvedValue({ element: { id: 'new-id', name: 'F' }, isCreation: true } as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_public_user_id: VALID_USER_ID, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await createFeed(mockContext, mockUser, input);
    expect(Middleware.createEntity).toHaveBeenCalled();
  });
});

describe('editFeed domain validation', () => {
  it('should throw when feed_public is true without feed_public_user_id', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ _index: 'idx', internal_id: 'feed-id', name: 'F' } as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(editFeed(mockContext, mockUser, 'feed-id', input)).rejects.toThrow('A user must be configured when the feed is public');
  });

  it('should throw when feed_public_user_id refers to a non-existent user', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ _index: 'idx', internal_id: 'feed-id', name: 'F' } as any);
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_public_user_id: NONEXISTENT_USER_ID, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(editFeed(mockContext, mockUser, 'feed-id', input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });
});

// ---------- StreamCollection ----------

describe('createStreamCollection domain validation', () => {
  it('should throw when stream_public is true without stream_public_user_id', async () => {
    const input = { name: 'S', stream_public: true } as StreamCollectionAddInput;
    await expect(createStreamCollection(mockContext, mockUser, input)).rejects.toThrow('A user must be configured when the stream collection is public');
  });

  it('should throw when stream_public_user_id refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'S', stream_public: true, stream_public_user_id: NONEXISTENT_USER_ID } as StreamCollectionAddInput;
    await expect(createStreamCollection(mockContext, mockUser, input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });
});

describe('streamCollectionEditField validation', () => {
  it('should throw when stream_public_user_id edit refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = [{ key: 'stream_public_user_id', value: [NONEXISTENT_USER_ID] }];
    await expect(streamCollectionEditField(mockContext, mockUser, 'col-id', input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should proceed when stream_public_user_id edit is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'S', id: 'col-id' } } as any);
    const input = [{ key: 'stream_public_user_id', value: [VALID_USER_ID] }];
    await streamCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });
});

// ---------- TaxiiCollection ----------

describe('createTaxiiCollection domain validation', () => {
  it('should throw when taxii_public is true without taxii_public_user_id', async () => {
    const input = { name: 'T', taxii_public: true } as TaxiiCollectionAddInput;
    await expect(createTaxiiCollection(mockContext, mockUser, input)).rejects.toThrow('A user must be configured when the Taxii collection is public');
  });

  it('should throw when taxii_public_user_id refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'T', taxii_public: true, taxii_public_user_id: NONEXISTENT_USER_ID } as TaxiiCollectionAddInput;
    await expect(createTaxiiCollection(mockContext, mockUser, input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });
});

describe('taxiiCollectionEditField validation', () => {
  it('should throw when taxii_public_user_id edit refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = [{ key: 'taxii_public_user_id', value: [NONEXISTENT_USER_ID] }];
    await expect(taxiiCollectionEditField(mockContext, mockUser, 'col-id', input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should proceed when taxii_public_user_id edit is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'T', id: 'col-id' } } as any);
    const input = [{ key: 'taxii_public_user_id', value: [VALID_USER_ID] }];
    await taxiiCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });
});
