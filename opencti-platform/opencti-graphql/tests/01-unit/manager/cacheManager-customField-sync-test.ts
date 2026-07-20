import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Capture the subscription callbacks registered by cacheManager's start()
type SubEvent = { instance: Record<string, unknown> };

const capturedHandlers: Record<string, ((event: SubEvent) => Promise<void>) | null> = {
  add: null,
  edit: null,
  delete: null,
};

const mockLoadCustomFieldDefinitions = vi.fn(async () => {});

const mockPubSubSubscription = vi.fn(async (topic: string, handler: any) => {
  if (topic.includes('ADDED_TOPIC')) {
    capturedHandlers.add = handler;
  } else if (topic.includes('EDIT_TOPIC')) {
    capturedHandlers.edit = handler;
  } else if (topic.includes('DELETE_TOPIC')) {
    capturedHandlers.delete = handler;
  }
  return { topic, unsubscribe: vi.fn() };
});

vi.mock('../../../src/modules/customField/custom-field-domain', () => ({
  loadCustomFieldDefinitions: mockLoadCustomFieldDefinitions,
}));

vi.mock('../../../src/database/redis', () => ({
  CACHE_RESET_TOPIC: 'TEST_PREFIX_CACHE_RESET_TOPIC',
  pubSubSubscription: (topic: string, handler: any) => mockPubSubSubscription(topic, handler),
}));

vi.mock('../../../src/database/cache', () => ({
  writeCacheForEntity: vi.fn(),
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

describe('cacheManager — custom field definitions sync', () => {
  beforeEach(() => {
    capturedHandlers.add = null;
    capturedHandlers.edit = null;
    capturedHandlers.delete = null;
    mockLoadCustomFieldDefinitions.mockClear();
    mockPubSubSubscription.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('reloads custom field definitions when a CustomFieldDefinition entity is ADDED', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');
    await cacheManager.start();

    expect(capturedHandlers.add).not.toBeNull();
    await capturedHandlers.add!({ instance: { entity_type: 'CustomFieldDefinition' } });

    expect(mockLoadCustomFieldDefinitions).toHaveBeenCalledTimes(1);
  });

  it('reloads custom field definitions when a CustomFieldDefinition entity is EDITED', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');
    await cacheManager.start();

    expect(capturedHandlers.edit).not.toBeNull();
    await capturedHandlers.edit!({ instance: { entity_type: 'CustomFieldDefinition' } });

    expect(mockLoadCustomFieldDefinitions).toHaveBeenCalledTimes(1);
  });

  it('reloads custom field definitions when a CustomFieldDefinition entity is DELETED', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');
    await cacheManager.start();

    expect(capturedHandlers.delete).not.toBeNull();
    await capturedHandlers.delete!({ instance: { entity_type: 'CustomFieldDefinition' } });

    expect(mockLoadCustomFieldDefinitions).toHaveBeenCalledTimes(1);
  });

  it('does NOT reload custom field definitions for other entity type events', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');
    await cacheManager.start();

    await capturedHandlers.add!({ instance: { entity_type: 'User' } });
    await capturedHandlers.edit!({ instance: { entity_type: 'Settings' } });
    await capturedHandlers.delete!({ instance: { entity_type: 'Malware' } });

    expect(mockLoadCustomFieldDefinitions).not.toHaveBeenCalled();
  });

  it('reloads custom field definitions when one of the instances in an array is a CustomFieldDefinition', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');
    await cacheManager.start();

    await capturedHandlers.add!({
      instance: [
        { entity_type: 'User' },
        { entity_type: 'CustomFieldDefinition' },
      ] as unknown as Record<string, unknown>,
    });

    expect(mockLoadCustomFieldDefinitions).toHaveBeenCalledTimes(1);
  });
});
