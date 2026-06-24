import { describe, expect, it } from 'vitest';
import { isLiveActivity } from '../../../src/manager/activityManager';
import type { ResolvedTrigger } from '../../../src/manager/notificationManager';

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

