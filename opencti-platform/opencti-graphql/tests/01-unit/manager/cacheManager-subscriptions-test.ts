import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';
import { createDatabaseCacheMock } from '../../utils/databaseCacheMock';
import { BUS_TOPICS, getBusTopicForEntityType } from '../../../src/config/conf';
import { STORE_ENTITIES_LINKS } from '../../../src/database/cache';
import { ABSTRACT_INTERNAL_OBJECT, ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../src/schema/general';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';

type TopicKey = 'ADDED_TOPIC' | 'EDIT_TOPIC' | 'DELETE_TOPIC';
const TOPIC_KEYS: TopicKey[] = ['ADDED_TOPIC', 'EDIT_TOPIC', 'DELETE_TOPIC'];

const defaultPubSubSubscription = async (topic: string, _handler: (event: any) => unknown) => ({ topic, unsubscribe: vi.fn() });
const mockPubSubSubscription = vi.fn(defaultPubSubSubscription);
const mockWriteCacheForEntity = vi.fn();
const mockAddCacheForEntity = vi.fn();
const mockRefreshCacheForEntity = vi.fn();
const mockRemoveCacheForEntity = vi.fn();

// Mock dependencies before importing cacheManager
vi.mock('../../../src/database/redis', () => ({
  CACHE_RESET_TOPIC: 'TEST_PREFIX_CACHE_RESET_TOPIC',
  pubSubSubscription: (topic: string, handler: any) => mockPubSubSubscription(topic, handler),
}));

// Keep the real STORE_ENTITIES_LINKS: the topics derived from its keys are part of what is under test
vi.mock('../../../src/database/cache', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return createDatabaseCacheMock({
    STORE_ENTITIES_LINKS: actual.STORE_ENTITIES_LINKS,
    writeCacheForEntity: (...args: unknown[]) => mockWriteCacheForEntity(...args),
    addCacheForEntity: (...args: unknown[]) => mockAddCacheForEntity(...args),
    refreshCacheForEntity: (...args: unknown[]) => mockRefreshCacheForEntity(...args),
    removeCacheForEntity: (...args: unknown[]) => mockRemoveCacheForEntity(...args),
  });
});

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

vi.mock('../../../src/modules/user/user-domain', () => ({
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

const expectedTopics = (entityTypes: string[], key: TopicKey): string[] => {
  const topics = entityTypes.map((entityType) => getBusTopicForEntityType(entityType)?.[key]).filter((topic): topic is string => !!topic);
  return [...new Set(topics)].sort();
};

// Replay an event on every add/edit/delete subscription to find out which cache operation each topic is wired to
const subscribedTopicsByKey = async (): Promise<Record<TopicKey, string[]>> => {
  const operations: Record<TopicKey, Mock> = {
    ADDED_TOPIC: mockAddCacheForEntity,
    EDIT_TOPIC: mockRefreshCacheForEntity,
    DELETE_TOPIC: mockRemoveCacheForEntity,
  };
  const subscribed: Record<TopicKey, string[]> = { ADDED_TOPIC: [], EDIT_TOPIC: [], DELETE_TOPIC: [] };
  const subscriptions = mockPubSubSubscription.mock.calls.filter(([topic]) => topic !== 'TEST_PREFIX_CACHE_RESET_TOPIC');
  for (const [topic, handler] of subscriptions) {
    Object.values(operations).forEach((operation) => operation.mockClear());
    const instance = { id: topic };
    await handler({ instance });
    const triggeredKeys = TOPIC_KEYS.filter((key) => operations[key].mock.calls.length > 0);
    expect(triggeredKeys, `topic ${topic} must trigger exactly one cache operation`).toHaveLength(1);
    expect(operations[triggeredKeys[0]]).toHaveBeenCalledWith(instance);
    subscribed[triggeredKeys[0]].push(topic);
  }
  return subscribed;
};

describe('cacheManager pub/sub topics subscriptions', () => {
  beforeEach(() => {
    mockPubSubSubscription.mockClear();
    mockPubSubSubscription.mockImplementation(defaultPubSubSubscription);
    mockWriteCacheForEntity.mockClear();
  });

  it('should subscribe to the topics of every cached entity type, ABSTRACT_INTERNAL_OBJECT and STORE_ENTITIES_LINKS keys', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');

    await cacheManager.start();

    // Every entity type written in cache must be kept in sync cluster-wide through its bus topics
    const cachedEntityTypes = mockWriteCacheForEntity.mock.calls.map(([entityType]) => entityType as string);
    expect(cachedEntityTypes).toContain(ENTITY_TYPE_USER);
    const linkedEntityTypes = Object.keys(STORE_ENTITIES_LINKS);
    expect(linkedEntityTypes).toContain(ENTITY_TYPE_LABEL);
    const entityTypes = [ABSTRACT_INTERNAL_OBJECT, ...cachedEntityTypes, ...linkedEntityTypes];

    const subscribed = await subscribedTopicsByKey();
    TOPIC_KEYS.forEach((key) => {
      expect([...subscribed[key]].sort(), `${key} subscriptions`).toEqual(expectedTopics(entityTypes, key));
    });
  });

  it('should listen to the shared internal object bus and linked entity types, but not to unrelated topics', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');

    await cacheManager.start();

    const subscribed = await subscribedTopicsByKey();
    // Shared bus used by internal objects that do not have their own topics
    expect(subscribed.ADDED_TOPIC).toContain(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].ADDED_TOPIC);
    expect(subscribed.EDIT_TOPIC).toContain(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC);
    expect(subscribed.DELETE_TOPIC).toContain(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC);
    // Labels are not cached but their modifications must reset the resolved filters (STORE_ENTITIES_LINKS)
    expect(subscribed.ADDED_TOPIC).toContain(BUS_TOPICS[ENTITY_TYPE_LABEL].ADDED_TOPIC);
    expect(subscribed.EDIT_TOPIC).toContain(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC);
    // Knowledge topics are not relevant for the cache, and wildcard patterns must not be used anymore
    const allTopics = TOPIC_KEYS.flatMap((key) => subscribed[key]);
    expect(allTopics).not.toContain(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC);
    expect(allTopics.filter((topic) => topic.includes('*'))).toEqual([]);
  });

  it('should release the already opened subscriptions when one of them fails on start', async () => {
    const { default: cacheManager } = await import('../../../src/manager/cacheManager');
    // Fail in the middle of the startup: add topics are subscribed, edit topics only partially
    const failingTopic = BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC;
    const unsubscribes: Mock[] = [];
    mockPubSubSubscription.mockImplementation(async (topic: string) => {
      if (topic === failingTopic) {
        throw new Error('Redis subscription failure');
      }
      const unsubscribe = vi.fn();
      unsubscribes.push(unsubscribe);
      return { topic, unsubscribe };
    });

    await expect(cacheManager.start()).rejects.toThrow('Redis subscription failure');

    expect(unsubscribes.length).toBeGreaterThan(0);
    unsubscribes.forEach((unsubscribe) => expect(unsubscribe).toHaveBeenCalledTimes(1));
    // Released subscriptions are no longer tracked, shutdown must not unsubscribe them twice
    await cacheManager.shutdown();
    unsubscribes.forEach((unsubscribe) => expect(unsubscribe).toHaveBeenCalledTimes(1));
  });
});
