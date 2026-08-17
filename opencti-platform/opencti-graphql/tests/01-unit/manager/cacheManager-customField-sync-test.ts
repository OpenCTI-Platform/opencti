import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockWriteCacheForEntity = vi.fn();
const mockPubSubSubscription = vi.fn(async (topic: string) => ({ topic, unsubscribe: vi.fn() }));

// Mock dependencies before importing cacheManager
vi.mock('../../../src/database/redis', () => ({
  CACHE_RESET_TOPIC: 'TEST_PREFIX_CACHE_RESET_TOPIC',
  pubSubSubscription: (topic: string) => mockPubSubSubscription(topic),
}));

vi.mock('../../../src/database/cache', () => ({
  writeCacheForEntity: (...args: unknown[]) => mockWriteCacheForEntity(...args),
  resetCacheForEntity: vi.fn(),
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

describe('cacheManager — custom field definitions registration', () => {
  beforeEach(() => {
    mockWriteCacheForEntity.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('registers CustomFieldDefinition in the generic cache, like any other cached entity type', async () => {
    // Custom field definitions no longer have a bespoke sync cache: they are registered in the
    // generic cache (database/cache.ts) and kept in sync cluster-wide via the same ADDED/EDIT/DELETE
    // pub/sub topics used by every other cached entity type (no special-casing needed anymore).
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');

    cacheManager.init();

    expect(mockWriteCacheForEntity).toHaveBeenCalledWith('CustomFieldDefinition', expect.objectContaining({ fn: expect.any(Function) }));
  });
});
