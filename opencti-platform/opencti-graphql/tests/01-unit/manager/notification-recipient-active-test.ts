/**
 * Unit tests for the notification-recipient account status validation.
 *
 * Bug fix: expired / disabled / inactive accounts must stop receiving notifications
 * (live + digest, email + in-app). Validation is enforced at the single choke point
 * `getNotifications`, which both the live (getLiveNotifications) and digest
 * (getDigestNotifications) pipelines build upon.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthUser } from '../../../src/types/user';

// ─── Cache mock: getNotifications reads triggers/users/settings from cache ─────
const getEntitiesListFromCache = vi.fn();
const getEntityFromCache = vi.fn();

vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: (...args: any[]) => getEntitiesListFromCache(...args),
  getEntityFromCache: (...args: any[]) => getEntityFromCache(...args),
}));

import { getNotifications, isNotificationRecipientActive } from '../../../src/manager/notificationManager';

import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';

import { ACCOUNT_STATUS_ACTIVE, ACCOUNT_STATUS_EXPIRED, ACCOUNT_STATUS_LOCKED } from '../../../src/config/conf';

import { utcDate } from '../../../src/utils/format';

const buildUser = (over: Partial<AuthUser>): AuthUser => ({
  id: 'user-x',
  internal_id: 'user-x',
  account_status: ACCOUNT_STATUS_ACTIVE,
  account_lock_after_date: undefined,
  groups: [],
  organizations: [],
  personal_notifiers: [],
  ...over,
} as unknown as AuthUser);

describe('isNotificationRecipientActive', () => {
  it('accepts an active, non-expired account', () => {
    expect(isNotificationRecipientActive(buildUser({ account_status: ACCOUNT_STATUS_ACTIVE }))).toBe(true);
  });

  it('rejects an account with a non-active status (expired)', () => {
    expect(isNotificationRecipientActive(buildUser({ account_status: ACCOUNT_STATUS_EXPIRED }))).toBe(false);
  });

  it('rejects an account with a non-active status (locked/disabled)', () => {
    expect(isNotificationRecipientActive(buildUser({ account_status: ACCOUNT_STATUS_LOCKED }))).toBe(false);
  });

  it('rejects an active account whose expiration date is in the past', () => {
    const past = utcDate().subtract(1, 'day').toISOString();
    expect(isNotificationRecipientActive(buildUser({ account_status: ACCOUNT_STATUS_ACTIVE, account_lock_after_date: past as any }))).toBe(false);
  });

  it('accepts an active account whose expiration date is in the future', () => {
    const future = utcDate().add(1, 'day').toISOString();
    expect(isNotificationRecipientActive(buildUser({ account_status: ACCOUNT_STATUS_ACTIVE, account_lock_after_date: future as any }))).toBe(true);
  });
});

describe('getNotifications — excludes inactive/expired accounts', () => {
  const context = {} as any;

  beforeEach(() => {
    vi.clearAllMocks();
    getEntityFromCache.mockResolvedValue({ platform_notifier_auto_trigger_assignee: true });
  });

  const collectUserIds = (triggers: Array<{ users: AuthUser[] }>): Set<string> => {
    const ids = new Set<string>();
    triggers.forEach((t) => t.users.forEach((u) => ids.add(u.id)));
    return ids;
  };

  it('keeps active users and drops inactive / expired ones from native triggers', async () => {
    const activeUser = buildUser({ id: 'active', internal_id: 'active', account_status: ACCOUNT_STATUS_ACTIVE });
    const disabledUser = buildUser({ id: 'disabled', internal_id: 'disabled', account_status: ACCOUNT_STATUS_LOCKED });
    const expiredStatusUser = buildUser({ id: 'expired-status', internal_id: 'expired-status', account_status: ACCOUNT_STATUS_EXPIRED });
    const expiredDateUser = buildUser({
      id: 'expired-date',
      internal_id: 'expired-date',
      account_status: ACCOUNT_STATUS_ACTIVE,
      account_lock_after_date: utcDate().subtract(1, 'day').toISOString() as any,
    });

    getEntitiesListFromCache.mockImplementation((_ctx: any, _user: any, type: string) => {
      if (type === ENTITY_TYPE_USER) {
        return Promise.resolve([activeUser, disabledUser, expiredStatusUser, expiredDateUser]);
      }
      return Promise.resolve([]); // no defined triggers
    });

    const triggers = await getNotifications(context);
    const ids = collectUserIds(triggers);

    expect(ids.has('active')).toBe(true);
    expect(ids.has('disabled')).toBe(false);
    expect(ids.has('expired-status')).toBe(false);
    expect(ids.has('expired-date')).toBe(false);
  });

  it('produces no triggers at all when every account is inactive', async () => {
    getEntitiesListFromCache.mockImplementation((_ctx: any, _user: any, type: string) => {
      if (type === ENTITY_TYPE_USER) {
        return Promise.resolve([
          buildUser({ id: 'u1', internal_id: 'u1', account_status: ACCOUNT_STATUS_EXPIRED }),
          buildUser({ id: 'u2', internal_id: 'u2', account_status: ACCOUNT_STATUS_LOCKED }),
        ]);
      }
      return Promise.resolve([]);
    });

    const triggers = await getNotifications(context);
    expect(collectUserIds(triggers).size).toBe(0);
  });

  it('excludes inactive users from a defined trigger targeting them by id', async () => {
    const activeUser = buildUser({ id: 'active', internal_id: 'active', account_status: ACCOUNT_STATUS_ACTIVE });
    const disabledUser = buildUser({ id: 'disabled', internal_id: 'disabled', account_status: ACCOUNT_STATUS_LOCKED });
    const definedTrigger = {
      internal_id: 'trigger-1',
      trigger_type: 'live',
      trigger_scope: 'knowledge',
      restricted_members: [{ id: 'active' }, { id: 'disabled' }],
    };

    getEntitiesListFromCache.mockImplementation((_ctx: any, _user: any, type: string) => {
      if (type === ENTITY_TYPE_USER) {
        return Promise.resolve([activeUser, disabledUser]);
      }
      return Promise.resolve([definedTrigger]); // one defined trigger
    });

    const triggers = await getNotifications(context);
    const definedResolved = triggers.find((t: any) => t.trigger.internal_id === 'trigger-1');
    const definedUserIds = new Set((definedResolved?.users ?? []).map((u: AuthUser) => u.id));
    expect(definedUserIds.has('active')).toBe(true);
    expect(definedUserIds.has('disabled')).toBe(false);
  });
});
