import { describe, expect, it } from 'vitest';
import { isLiveActivity, resolveActivitySourceUser } from '../../../src/manager/activityManager';
import type { ResolvedTrigger } from '../../../src/manager/notificationManager';
import { INGESTION_HEALTH_MANAGER_USER, SYSTEM_USER } from '../../../src/utils/access';
import type { AuthUser } from '../../../src/types/user';

const buildResolvedTrigger = (trigger_type: string, trigger_scope: string): ResolvedTrigger => {
  return {
    users: [],
    trigger: {
      internal_id: 'test-trigger-id',
      name: 'Test trigger',
      trigger_type,
      trigger_scope,
      notifiers: [],
      restricted_members: [],
    },
  } as unknown as ResolvedTrigger;
};

describe('Activity manager - isLiveActivity', () => {
  it('should return true for a live activity trigger', () => {
    const trigger = buildResolvedTrigger('live', 'activity');
    expect(isLiveActivity(trigger)).toBe(true);
  });

  it('should return false for a live knowledge trigger', () => {
    const trigger = buildResolvedTrigger('live', 'knowledge');
    expect(isLiveActivity(trigger)).toBe(false);
  });

  it('should return false for a live internal trigger', () => {
    const trigger = buildResolvedTrigger('live', 'internal');
    expect(isLiveActivity(trigger)).toBe(false);
  });

  it('should return false for a digest trigger with activity scope', () => {
    const trigger = buildResolvedTrigger('digest', 'activity');
    expect(isLiveActivity(trigger)).toBe(false);
  });

  it('should return false for a digest trigger with knowledge scope', () => {
    const trigger = buildResolvedTrigger('digest', 'knowledge');
    expect(isLiveActivity(trigger)).toBe(false);
  });
});

describe('Activity manager - resolveActivitySourceUser', () => {
  const platformUser = { id: 'platform-user-id', name: 'Platform user' } as AuthUser;
  const platformUsers = new Map([[platformUser.id, platformUser]]);

  it('should resolve an internal user absent from the users cache', () => {
    expect(resolveActivitySourceUser(INGESTION_HEALTH_MANAGER_USER.id, platformUsers)?.name).toBe('INGESTION HEALTH MANAGER');
  });

  it('should resolve a platform user from the users cache', () => {
    expect(resolveActivitySourceUser(platformUser.id, platformUsers)).toBe(platformUser);
  });

  it('should resolve the system user when the event has no user', () => {
    expect(resolveActivitySourceUser(undefined, platformUsers)).toBe(SYSTEM_USER);
  });
});
