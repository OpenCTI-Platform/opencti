import { describe, it, expect, vi } from 'vitest';
import { createFeed } from '../../../../src/modules/dataSharing/feed-domain';
import { createStreamCollection } from '../../../../src/modules/dataSharing/streamCollection-domain';
import { createTaxiiCollection } from '../../../../src/modules/dataSharing/taxiiCollection-domain';
import type { FeedAddInput, StreamCollectionAddInput, TaxiiCollectionAddInput } from '../../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../../src/utils/access';

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  deleteElementById: vi.fn(),
  updateAttribute: vi.fn(),
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

describe('createFeed domain validation', () => {
  it('should throw FunctionalError when feed_public is true without feed_public_user_id', async () => {
    const input: Partial<FeedAddInput> = {
      name: 'Public Feed',
      separator: ',',
      feed_types: [],
      feed_attributes: [],
      feed_public: true,
      feed_public_user_id: undefined,
      rolling_time: 60,
      include_header: false,
    };

    await expect(createFeed(mockContext, mockUser, input as FeedAddInput))
      .rejects.toThrow('A user must be configured when the feed is public');
  });
});

describe('createStreamCollection domain validation', () => {
  it('should throw FunctionalError when stream_public is true without stream_public_user_id', async () => {
    const input: Partial<StreamCollectionAddInput> = {
      name: 'Public Stream',
      stream_public: true,
      stream_public_user_id: undefined,
    };

    await expect(createStreamCollection(mockContext, mockUser, input as StreamCollectionAddInput))
      .rejects.toThrow('A user must be configured when the stream collection is public');
  });
});

describe('createTaxiiCollection domain validation', () => {
  it('should throw FunctionalError when taxii_public is true without taxii_public_user_id', async () => {
    const input: Partial<TaxiiCollectionAddInput> = {
      name: 'Public Taxii',
      taxii_public: true,
      taxii_public_user_id: undefined,
    };

    await expect(createTaxiiCollection(mockContext, mockUser, input as TaxiiCollectionAddInput))
      .rejects.toThrow('A user must be configured when the Taxii collection is public');
  });
});
