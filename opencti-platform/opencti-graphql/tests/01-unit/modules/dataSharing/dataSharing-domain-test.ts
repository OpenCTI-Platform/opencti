import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Middleware from '../../../../src/database/middleware';
import * as MiddlewareLoader from '../../../../src/database/middleware-loader';
import { createFeed, editFeed } from '../../../../src/modules/dataSharing/feed-domain';
import { createStreamCollection, streamCollectionEditField } from '../../../../src/modules/dataSharing/streamCollection-domain';
import { createTaxiiCollection, taxiiCollectionEditField } from '../../../../src/modules/dataSharing/taxiiCollection-domain';
import type { FeedAddInput, StreamCollectionAddInput, TaxiiCollectionAddInput } from '../../../../src/generated/graphql';
import { SYSTEM_USER, TAXIIAPI_SETCOLLECTIONS } from '../../../../src/utils/access';

// A user with only TAXIIAPI_SETCOLLECTIONS but NOT SETTINGS_SET_ACCESSES
const mockLimitedUser = {
  ...SYSTEM_USER,
  capabilities: [{ name: TAXIIAPI_SETCOLLECTIONS }],
} as any;

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

  it('should throw when user lacks SETTINGS_SET_ACCESSES and feed_public is true', async () => {
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(createFeed(mockContext, mockLimitedUser, input)).rejects.toThrow('You must have the SETTINGS_SETACCESSES capability to create a public feed');
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

  it('should throw when user lacks SETTINGS_SET_ACCESSES and public fields changed', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ _index: 'idx', internal_id: 'feed-id', name: 'F', feed_public: false } as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(editFeed(mockContext, mockLimitedUser, 'feed-id', input)).rejects.toThrow('You must have the SETTINGS_SETACCESSES capability to modify public feed settings');
  });

  it('should throw when feed_public_user_id refers to a non-existent user', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ _index: 'idx', internal_id: 'feed-id', name: 'F' } as any);
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_public_user_id: NONEXISTENT_USER_ID, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(editFeed(mockContext, mockUser, 'feed-id', input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should throw when feed does not exist', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(undefined as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: false, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await expect(editFeed(mockContext, mockUser, 'missing-id', input)).rejects.toThrow('Feed missing-id cant be found');
  });

  it('should succeed when feed_public_user_id is valid', async () => {
    const mockFeed = { _index: 'idx', internal_id: 'feed-id', name: 'F' } as any;
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue(mockFeed);
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    const input = { name: 'F', separator: ',', feed_types: [], feed_attributes: [], feed_public: true, feed_public_user_id: VALID_USER_ID, feed_date_attribute: 'created_at', rolling_time: 60, include_header: false } as FeedAddInput;
    await editFeed(mockContext, mockUser, 'feed-id', input);
    expect(MiddlewareLoader.storeLoadById).toHaveBeenCalled();
  });
});

// ---------- StreamCollection ----------

describe('createStreamCollection domain validation', () => {
  it('should throw when stream_public is true without stream_public_user_id', async () => {
    const input = { name: 'S', stream_public: true } as StreamCollectionAddInput;
    await expect(createStreamCollection(mockContext, mockUser, input)).rejects.toThrow('A user must be configured when the stream collection is public');
  });

  it('should throw when user lacks SETTINGS_SET_ACCESSES and stream_public is true', async () => {
    const input = { name: 'S', stream_public: true } as StreamCollectionAddInput;
    await expect(createStreamCollection(mockContext, mockLimitedUser, input)).rejects.toThrow('You must have the SETTINGS_SETACCESSES capability to create a public stream collection');
  });

  it('should throw when stream_public_user_id refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'S', stream_public: true, stream_public_user_id: NONEXISTENT_USER_ID } as StreamCollectionAddInput;
    await expect(createStreamCollection(mockContext, mockUser, input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should call createEntity when stream_public_user_id is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.createEntity).mockResolvedValue({ element: { id: 'new-stream-id', name: 'S' }, isCreation: true } as any);
    const input = { name: 'S', stream_public: true, stream_public_user_id: VALID_USER_ID } as StreamCollectionAddInput;
    await createStreamCollection(mockContext, mockUser, input);
    expect(Middleware.createEntity).toHaveBeenCalled();
  });

  it('should call createEntity when stream is not public (no user validation needed)', async () => {
    vi.mocked(Middleware.createEntity).mockResolvedValue({ element: { id: 'new-stream-id', name: 'S' }, isCreation: false } as any);
    const input = { name: 'S', stream_public: false } as StreamCollectionAddInput;
    await createStreamCollection(mockContext, mockUser, input);
    expect(Middleware.createEntity).toHaveBeenCalled();
  });
});

describe('streamCollectionEditField validation', () => {
  it('should throw when stream_public_user_id edit refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = [{ key: 'stream_public_user_id', value: [NONEXISTENT_USER_ID] }];
    await expect(streamCollectionEditField(mockContext, mockUser, 'col-id', input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should throw when user lacks SETTINGS_SET_ACCESSES and public fields are in edit input', async () => {
    const input = [{ key: 'stream_public', value: ['true'] }];
    await expect(streamCollectionEditField(mockContext, mockLimitedUser, 'col-id', input)).rejects.toThrow('You must have the SETTINGS_SETACCESSES capability to modify public stream collection settings');
  });

  it('should proceed when stream_public_user_id edit is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'S', id: 'col-id' } } as any);
    const input = [{ key: 'stream_public_user_id', value: [VALID_USER_ID] }];
    await streamCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });

  it('should proceed without user validation when stream_public_user_id is not in the edit input', async () => {
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'S', id: 'col-id' } } as any);
    const input = [{ key: 'name', value: ['Updated stream'] }];
    await streamCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
    expect(Cache.getEntitiesMapFromCache).not.toHaveBeenCalled();
  });

  it('should throw when setting stream_public to true but no user ID in input and no user ID on existing collection', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ id: 'col-id', name: 'S', stream_public_user_id: undefined } as any);
    const input = [{ key: 'stream_public', value: ['true'] }];
    await expect(streamCollectionEditField(mockContext, mockUser, 'col-id', input)).rejects.toThrow('A user must be configured when the stream collection is public');
  });

  it('should proceed when setting stream_public to true and existing collection already has a user ID', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ id: 'col-id', name: 'S', stream_public_user_id: VALID_USER_ID } as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'S', id: 'col-id' } } as any);
    const input = [{ key: 'stream_public', value: ['true'] }];
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

  it('should throw when user lacks SETTINGS_SET_ACCESSES and taxii_public is true', async () => {
    const input = { name: 'T', taxii_public: true } as TaxiiCollectionAddInput;
    await expect(createTaxiiCollection(mockContext, mockLimitedUser, input)).rejects.toThrow('You must have the SETTINGS_SETACCESSES capability to create a public Taxii collection');
  });

  it('should throw when taxii_public_user_id refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = { name: 'T', taxii_public: true, taxii_public_user_id: NONEXISTENT_USER_ID } as TaxiiCollectionAddInput;
    await expect(createTaxiiCollection(mockContext, mockUser, input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should call createEntity when taxii_public_user_id is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.createEntity).mockResolvedValue({ element: { id: 'new-taxii-id', name: 'T' }, isCreation: true } as any);
    const input = { name: 'T', taxii_public: true, taxii_public_user_id: VALID_USER_ID } as TaxiiCollectionAddInput;
    await createTaxiiCollection(mockContext, mockUser, input);
    expect(Middleware.createEntity).toHaveBeenCalled();
  });

  it('should call createEntity when taxii collection is not public (no user validation needed)', async () => {
    vi.mocked(Middleware.createEntity).mockResolvedValue({ element: { id: 'new-taxii-id', name: 'T' }, isCreation: false } as any);
    const input = { name: 'T', taxii_public: false } as TaxiiCollectionAddInput;
    await createTaxiiCollection(mockContext, mockUser, input);
    expect(Middleware.createEntity).toHaveBeenCalled();
  });
});

describe('taxiiCollectionEditField validation', () => {
  it('should throw when taxii_public_user_id edit refers to a non-existent user', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map() as any);
    const input = [{ key: 'taxii_public_user_id', value: [NONEXISTENT_USER_ID] }];
    await expect(taxiiCollectionEditField(mockContext, mockUser, 'col-id', input)).rejects.toThrow('The user configured for this public sharing no longer exists');
  });

  it('should throw when user lacks SETTINGS_SET_ACCESSES and public fields are in edit input', async () => {
    const input = [{ key: 'taxii_public', value: ['true'] }];
    await expect(taxiiCollectionEditField(mockContext, mockLimitedUser, 'col-id', input)).rejects.toThrow('You must have the SETTINGS_SETACCESSES capability to modify public Taxii collection settings');
  });

  it('should proceed when taxii_public_user_id edit is valid', async () => {
    vi.mocked(Cache.getEntitiesMapFromCache).mockResolvedValue(new Map([[VALID_USER_ID, mockRealUser]]) as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'T', id: 'col-id' } } as any);
    const input = [{ key: 'taxii_public_user_id', value: [VALID_USER_ID] }];
    await taxiiCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });

  it('should proceed without user validation when taxii_public_user_id is not in the edit input', async () => {
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'T', id: 'col-id' } } as any);
    const input = [{ key: 'name', value: ['Updated taxii'] }];
    await taxiiCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
    expect(Cache.getEntitiesMapFromCache).not.toHaveBeenCalled();
  });

  it('should throw when setting taxii_public to true but no user ID in input and no user ID on existing collection', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ id: 'col-id', name: 'T', taxii_public_user_id: undefined } as any);
    const input = [{ key: 'taxii_public', value: ['true'] }];
    await expect(taxiiCollectionEditField(mockContext, mockUser, 'col-id', input)).rejects.toThrow('A user must be configured when the Taxii collection is public');
  });

  it('should proceed when setting taxii_public to true and existing collection already has a user ID', async () => {
    vi.mocked(MiddlewareLoader.storeLoadById).mockResolvedValue({ id: 'col-id', name: 'T', taxii_public_user_id: VALID_USER_ID } as any);
    vi.mocked(Middleware.updateAttribute).mockResolvedValue({ element: { name: 'T', id: 'col-id' } } as any);
    const input = [{ key: 'taxii_public', value: ['true'] }];
    await taxiiCollectionEditField(mockContext, mockUser, 'col-id', input);
    expect(Middleware.updateAttribute).toHaveBeenCalled();
  });
});
