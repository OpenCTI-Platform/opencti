import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityTrigger } from '../../../src/modules/notification/notification-types';

// Mock the stream layer to capture the stored digest events (no Redis needed).
vi.mock('../../../src/database/stream/stream-handler', () => ({
  fetchRangeNotifications: vi.fn(),
  storeNotificationEvent: vi.fn(),
  createStreamProcessor: vi.fn(),
}));

// Mock the cache so the triggers and their recipients are canned (no ElasticSearch needed).
vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntityFromCache: vi.fn(),
}));

// Mock the landscape diff of a change digest: the orchestration of the manager is under test.
const buildChangeDigestDataMock = vi.fn();
vi.mock('../../../src/modules/timeMachine/timeMachine-changeDigest', () => ({
  TRIGGER_TYPE_CHANGE_DIGEST: 'change_digest',
  buildChangeDigestData: (...args: unknown[]) => buildChangeDigestDataMock(...args),
}));

import { handleChangeDigestNotifications } from '../../../src/manager/notificationManager';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { storeNotificationEvent } from '../../../src/database/stream/stream-handler';
import { ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';
import { ACCOUNT_STATUS_ACTIVE } from '../../../src/config/conf';

interface StoredDigestEvent {
  type: string;
  notification_id: string;
  target: { user_id: string; notifiers: string[] };
  data: unknown[];
}

describe('handleChangeDigestNotifications', () => {
  // Monday 09:00 UTC, aligned with the weekly trigger time of the change digest
  const FROZEN = new Date('2026-01-12T09:00:00.000Z');

  const buildUser = (id: string) => ({
    id,
    internal_id: id,
    user_email: `${id}@local`,
    user_service_account: false,
    groups: [],
    organizations: [],
    personal_notifiers: [],
    account_status: ACCOUNT_STATUS_ACTIVE,
  } as unknown as AuthUser);
  const analyst = buildUser('analyst-1');
  const manager = buildUser('manager-1');

  const changeDigest = {
    internal_id: 'change-digest-1',
    id: 'change-digest-1',
    name: 'Weekly landscape',
    trigger_type: 'change_digest',
    period: 'week',
    trigger_time: '1-09:00:00.000Z',
    filters: null,
    scope_entity_types: ['Intrusion-Set'],
    notifiers: ['notifier-ui'],
    restricted_members: [{ id: analyst.id }, { id: manager.id }],
  } as unknown as BasicStoreEntityTrigger;
  const regularDigest = { ...changeDigest, internal_id: 'digest-1', id: 'digest-1', trigger_type: 'digest', trigger_ids: [] } as unknown as BasicStoreEntityTrigger;
  const digestLine = { notification_id: 'change-digest-1', instance: { id: 'intrusion-set--1' }, type: 'update', message: '`2` new relationship(s)' };

  const primeCache = (triggers: BasicStoreEntityTrigger[]) => {
    const resolveFromCache = (_ctx: AuthContext, _user: AuthUser, type: string) => {
      return Promise.resolve(type === ENTITY_TYPE_TRIGGER ? triggers : [analyst, manager]);
    };
    vi.mocked(getEntitiesListFromCache).mockImplementation(resolveFromCache as unknown as typeof getEntitiesListFromCache);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_notifier_auto_trigger_assignee: true } as unknown as Awaited<ReturnType<typeof getEntityFromCache>>);
  };

  const storedEvents = () => vi.mocked(storeNotificationEvent).mock.calls.map((call) => call[1] as unknown as StoredDigestEvent);

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FROZEN);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('computes the digest of each recipient with their own rights over the last period and stores it', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => (recipient.id === analyst.id ? [digestLine] : []));
    await handleChangeDigestNotifications({} as AuthContext);
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(2);
    expect(buildChangeDigestDataMock.mock.calls.map((call) => (call[1] as AuthUser).id).sort()).toEqual([analyst.id, manager.id]);
    buildChangeDigestDataMock.mock.calls.forEach(([, , trigger, from, to]) => {
      expect((trigger as BasicStoreEntityTrigger).internal_id).toBe('change-digest-1');
      expect(from).toBe('2026-01-05T09:00:00.000Z');
      expect(to).toBe('2026-01-12T09:00:00.000Z');
    });
    // Only the recipient with changes in the period receives a digest
    const events = storedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('digest');
    expect(events[0].notification_id).toBe('change-digest-1');
    expect(events[0].target.user_id).toBe(analyst.id);
    expect(events[0].target.notifiers).toEqual(['notifier-ui']);
    expect(events[0].data).toEqual([digestLine]);
  });

  it('ignores the change digests that are not due and the regular digests', async () => {
    primeCache([{ ...changeDigest, trigger_time: '2-09:00:00.000Z' } as unknown as BasicStoreEntityTrigger, regularDigest]);
    await handleChangeDigestNotifications({} as AuthContext);
    expect(buildChangeDigestDataMock).not.toHaveBeenCalled();
    expect(vi.mocked(storeNotificationEvent)).not.toHaveBeenCalled();
  });

  it('keeps serving the other recipients when the digest of one recipient fails', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => {
      if (recipient.id === analyst.id) throw new Error('landscape diff failed');
      return [digestLine];
    });
    await handleChangeDigestNotifications({} as AuthContext);
    const events = storedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].target.user_id).toBe(manager.id);
  });
});
