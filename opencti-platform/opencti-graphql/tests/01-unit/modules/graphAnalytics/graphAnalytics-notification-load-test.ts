import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getLiveNotifications: vi.fn(),
  elList: vi.fn(),
  loadGraphClusters: vi.fn(),
  storeLoadByIdsWithRefs: vi.fn(),
  storeNotificationEvent: vi.fn(),
}));

vi.mock('../../../../src/manager/notificationManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/notificationManager')>()),
  getLiveNotifications: mocks.getLiveNotifications,
  convertToNotificationUser: (user: { id: string }) => ({ user_id: user.id }),
}));
vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elList: mocks.elList,
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  storeLoadByIdsWithRefs: mocks.storeLoadByIdsWithRefs,
}));
vi.mock('../../../../src/database/stix-common-converter', () => ({
  convertStoreToStix: (instance: { internal_id: string }) => ({ id: instance.internal_id, name: instance.internal_id }),
}));
vi.mock('../../../../src/database/stix-representative', () => ({
  extractStixRepresentative: (stix: { name: string }) => stix.name,
}));
vi.mock('../../../../src/database/cache', () => ({ getEntityFromCache: vi.fn(async () => ({})) }));
vi.mock('../../../../src/database/stream/stream-handler', () => ({ storeNotificationEvent: mocks.storeNotificationEvent }));
vi.mock('../../../../src/utils/filtering/filtering-stix/stix-filtering', () => ({ isStixMatchFilterGroup: vi.fn(async () => true) }));
vi.mock('../../../../src/utils/access', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/utils/access')>()),
  isUserCanAccessStixElement: vi.fn(async () => true),
  isUserInPlatformOrganization: vi.fn(() => true),
}));
vi.mock('../../../../src/modules/graphAnalytics/graphAnalytics-store', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/graphAnalytics/graphAnalytics-store')>()),
  loadGraphClusters: mocks.loadGraphClusters,
}));

const { notifyGraphClusterJoined } = await import('../../../../src/modules/graphAnalytics/graphAnalytics-notification');

const context = {} as never;
const joinedMember = (id: string, clusterId: string) => ({ internal_id: id, x_opencti_graph_metrics: { cluster_id: clusterId } });

describe('graph analytics cluster joined notifications', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getLiveNotifications.mockResolvedValue([
      { trigger: { internal_id: 'trigger-1', event_types: ['graph_cluster_joined'], filters: null, raw_filters: null, notifiers: [] }, users: [{ id: 'analyst' }] },
    ]);
    mocks.loadGraphClusters.mockResolvedValue([{ internal_id: 'cluster-a', name: 'Cluster A' }]);
  });

  it('should load the joined entities in one bulk request, skipping those of an unknown cluster', async () => {
    mocks.elList.mockResolvedValue([joinedMember('ip-1', 'cluster-a'), joinedMember('ip-2', 'cluster-a'), joinedMember('ip-3', 'cluster-gone')]);
    mocks.storeLoadByIdsWithRefs.mockResolvedValue([{ internal_id: 'ip-2' }, { internal_id: 'ip-1' }]);
    const delivered = await notifyGraphClusterJoined(context, '2026-10-05T06:00:00.000Z');
    expect(mocks.storeLoadByIdsWithRefs).toHaveBeenCalledTimes(1);
    expect(mocks.storeLoadByIdsWithRefs.mock.calls[0][2]).toEqual(['ip-1', 'ip-2']);
    expect(delivered).toBe(2);
    expect(mocks.storeNotificationEvent.mock.calls.map(([, event]) => event.streamMessage)).toEqual([
      '[graph analytics] `ip-1` joined the cluster `Cluster A`',
      '[graph analytics] `ip-2` joined the cluster `Cluster A`',
    ]);
  });

  it('should not load anything when no joined entity belongs to a known cluster', async () => {
    mocks.elList.mockResolvedValue([joinedMember('ip-3', 'cluster-gone')]);
    expect(await notifyGraphClusterJoined(context, '2026-10-05T06:00:00.000Z')).toBe(0);
    expect(mocks.storeLoadByIdsWithRefs).not.toHaveBeenCalled();
  });
});
