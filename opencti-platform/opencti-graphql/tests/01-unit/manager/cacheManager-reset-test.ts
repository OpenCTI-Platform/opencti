import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Capture the subscription callback registered by cacheManager
let capturedResetHandler: ((event: { entityType: string }) => void) | null = null;

const mockPubSubSubscription = vi.fn(async (topic: string, handler: any) => {
  if (topic.includes('CACHE_RESET_TOPIC')) {
    capturedResetHandler = handler;
  }
  return { topic, unsubscribe: vi.fn() };
});

const mockResetCacheForEntity = vi.fn();
const mockWriteCacheForEntity = vi.fn();

// Mock dependencies before importing cacheManager
vi.mock('../../../src/database/redis', () => ({
  CACHE_RESET_TOPIC: 'TEST_PREFIX_CACHE_RESET_TOPIC',
  pubSubSubscription: (topic: string, handler: any) => mockPubSubSubscription(topic, handler),
}));

vi.mock('../../../src/database/cache', () => ({
  writeCacheForEntity: (...args: unknown[]) => mockWriteCacheForEntity(...args),
  resetCacheForEntity: (...args: unknown[]) => mockResetCacheForEntity(...args),
  addCacheForEntity: vi.fn(),
  refreshCacheForEntity: vi.fn(),
  removeCacheForEntity: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    logApp: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
    TOPIC_PREFIX: 'TEST_PREFIX_',
  };
});

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(async () => []),
  fullRelationsList: vi.fn(async () => []),
  internalFindByIds: vi.fn(async () => []),
  pageEntitiesConnection: vi.fn(),
}));

vi.mock('../../../src/database/middleware', () => ({
  stixLoadByIds: vi.fn(async () => []),
}));

vi.mock('../../../src/database/repository', () => ({
  connectors: vi.fn(async () => []),
}));

vi.mock('../../../src/domain/user', () => ({
  buildCompleteUsers: vi.fn(async () => []),
  resolveUserById: vi.fn(async () => ({})),
}));

vi.mock('../../../src/modules/notifier/notifier-statics', () => ({
  STATIC_NOTIFIERS: [],
}));

vi.mock('../../../src/modules/publicDashboard/publicDashboard-domain', () => ({
  getAllowedMarkings: vi.fn(async () => []),
}));

vi.mock('../../../src/modules/settings/licensing', () => ({
  getEnterpriseEditionInfo: vi.fn(() => ({ license_validated: false })),
}));

vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({})),
  SYSTEM_USER: { id: 'system' },
}));

vi.mock('../../../src/utils/base64', () => ({
  fromB64: vi.fn((v: string) => v),
}));

describe('cacheManager subscribeReset', () => {
  beforeEach(() => {
    capturedResetHandler = null;
    mockResetCacheForEntity.mockClear();
    mockPubSubSubscription.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should subscribe to CACHE_RESET_TOPIC on start and call resetCacheForEntity on event', async () => {
    // Dynamically import cacheManager so mocks are in place
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');

    await cacheManager.start();

    // Verify subscription was created for the reset topic
    expect(mockPubSubSubscription).toHaveBeenCalledWith(
      'TEST_PREFIX_CACHE_RESET_TOPIC',
      expect.any(Function),
    );

    // Verify the handler was captured
    expect(capturedResetHandler).not.toBeNull();

    // Simulate receiving a cache reset event
    capturedResetHandler!({ entityType: 'User' });

    // Verify resetCacheForEntity was called with the correct entity type
    expect(mockResetCacheForEntity).toHaveBeenCalledWith('User');
  });

  it('should call resetCacheForEntity for each distinct event entity type', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');

    await cacheManager.start();
    expect(capturedResetHandler).not.toBeNull();

    // Simulate multiple reset events
    capturedResetHandler!({ entityType: 'User' });
    capturedResetHandler!({ entityType: 'Settings' });
    capturedResetHandler!({ entityType: 'User' });

    expect(mockResetCacheForEntity).toHaveBeenCalledTimes(3);
    expect(mockResetCacheForEntity).toHaveBeenCalledWith('User');
    expect(mockResetCacheForEntity).toHaveBeenCalledWith('Settings');
  });
});
