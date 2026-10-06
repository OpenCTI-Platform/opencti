import { beforeEach, describe, expect, it, vi } from 'vitest';

interface CachedUser {
  internal_id: string;
  capabilities: { name: string }[];
}

interface UserCache {
  values: CachedUser[];
  refresh: (values: CachedUser[], instance: CachedUser) => Promise<CachedUser[]>;
  add: (values: CachedUser[], instance: CachedUser) => Promise<CachedUser[]>;
  remove: (values: CachedUser[], instance: CachedUser) => Promise<CachedUser[]>;
}

const { stores, loadUsers, resolveUser } = vi.hoisted(() => ({
  stores: new Map<string, UserCache>(),
  loadUsers: vi.fn(),
  resolveUser: vi.fn(),
}));

vi.mock('../../../src/database/cache', () => ({
  writeCacheForEntity: (type: string, store: UserCache) => stores.set(type, store),
  resetCacheForEntity: vi.fn(),
  addCacheForEntity: vi.fn(),
  refreshCacheForEntity: vi.fn(),
  removeCacheForEntity: vi.fn(),
}));
vi.mock('../../../src/database/redis', () => ({
  CACHE_RESET_TOPIC: 'CACHE_RESET_TOPIC',
  pubSubSubscription: vi.fn(),
}));
vi.mock('../../../src/database/middleware-loader', () => ({
  internalFindByIds: (_context: unknown, _user: unknown, ids: string[]) => loadUsers(ids),
  fullEntitiesList: vi.fn(),
  fullRelationsList: vi.fn(),
}));
vi.mock('../../../src/database/middleware', () => ({ stixLoadByIds: vi.fn() }));
vi.mock('../../../src/database/repository', () => ({ connectors: vi.fn() }));
vi.mock('../../../src/domain/user', () => ({
  buildCompleteUsers: (_context: unknown, users: CachedUser[]) => users,
  resolveUserById: (_context: unknown, id: string) => resolveUser(id),
}));
vi.mock('../../../src/modules/notifier/notifier-statics', () => ({ STATIC_NOTIFIERS: [] }));
vi.mock('../../../src/modules/publicDashboard/publicDashboard-domain', () => ({ getAllowedMarkings: vi.fn() }));
vi.mock('../../../src/modules/settings/licensing', () => ({ getEnterpriseEditionInfo: vi.fn() }));
vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({})),
  SYSTEM_USER: { id: 'system' },
}));
vi.mock('../../../src/utils/base64', () => ({ fromB64: vi.fn() }));

import cacheManager from '../../../src/manager/cacheManager';

const user = (id: string, capability = 'KNOWLEDGE'): CachedUser => ({
  internal_id: id,
  capabilities: [{ name: capability }],
});

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

describe('User cache concurrent updates', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    cacheManager.init();
  });

  it('preserves both users permissions when refreshes overlap', async () => {
    const store = stores.get('User')!;
    const first = user('first');
    const second = user('second');
    store.values = [first, second];
    const firstLoad = deferred<CachedUser[]>();
    const secondLoad = deferred<CachedUser[]>();
    loadUsers.mockImplementation((ids: string[]) => ids[0] === 'first' ? firstLoad.promise : secondLoad.promise);

    const refresh = async (instance: CachedUser) => {
      store.values = await store.refresh(store.values, instance);
    };
    const firstRefresh = refresh(first);
    const secondRefresh = refresh(second);
    const firstUpdated = user('first', 'SETTINGS_SETCUSTOMIZATION');
    const secondUpdated = user('second', 'KNOWLEDGE_KNUPDATE');
    firstLoad.resolve([firstUpdated]);
    await firstRefresh;
    secondLoad.resolve([secondUpdated]);
    await secondRefresh;

    expect(store.values).toEqual(expect.arrayContaining([firstUpdated, secondUpdated]));
    expect(store.values).toHaveLength(2);
  });

  it('preserves a newly cached user while another user refresh is pending', async () => {
    const store = stores.get('User')!;
    const first = user('first');
    const second = user('second');
    store.values = [first];
    const pendingLoad = deferred<CachedUser[]>();
    loadUsers.mockReturnValue(pendingLoad.promise);
    resolveUser.mockResolvedValue(second);
    const refresh = store.refresh(store.values, first);
    store.values = await store.add(store.values, second);
    const updated = user('first', 'SETTINGS_SETCUSTOMIZATION');
    pendingLoad.resolve([updated]);
    store.values = await refresh;

    expect(store.values).toEqual(expect.arrayContaining([updated, second]));
    expect(store.values).toHaveLength(2);
  });

  it('does not restore a removed user when another user refresh completes', async () => {
    const store = stores.get('User')!;
    const first = user('first');
    const second = user('second');
    store.values = [first, second];
    const pendingLoad = deferred<CachedUser[]>();
    loadUsers.mockReturnValue(pendingLoad.promise);
    const refresh = store.refresh(store.values, first);
    store.values = await store.remove(store.values, second);
    const updated = user('first', 'SETTINGS_SETCUSTOMIZATION');
    pendingLoad.resolve([updated]);
    store.values = await refresh;

    expect(store.values).toEqual([updated]);
  });

  it('does not duplicate a user when local and subscription additions overlap', async () => {
    const store = stores.get('User')!;
    store.values = [];
    const addedUser = user('first');
    const pendingLoad = deferred<CachedUser>();
    resolveUser.mockReturnValue(pendingLoad.promise);
    const firstAdd = store.add(store.values, addedUser);
    const secondAdd = store.add(store.values, addedUser);
    pendingLoad.resolve(addedUser);
    await Promise.all([firstAdd, secondAdd]);

    expect(store.values).toEqual([addedUser]);
  });
});
