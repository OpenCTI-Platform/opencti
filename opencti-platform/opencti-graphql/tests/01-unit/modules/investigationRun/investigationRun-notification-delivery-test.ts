import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InvestigationRunStatus } from '../../../../src/generated/graphql';
import { buildRun } from './investigationRun-fixtures';

type User = { id: string; personal_notifiers?: string[] };
const access = vi.hoisted(() => ({
  readsCase: new Set<string>(),
  readsRun: new Set<string>(),
  matchesFilter: new Set<string>(),
  liveCase: true,
  triggers: [] as Array<{ users: User[]; trigger: { internal_id: string; event_types: string[]; filters: string; notifiers: string[] } }>,
  stored: [] as Array<{ notification_id: string; targets: Array<{ user: { user_id: string }; type: string; message: string }> }>,
}));

vi.mock('../../../../src/manager/notificationManager', () => ({
  EVENT_NOTIFICATION_VERSION: '1',
  getLiveNotifications: async () => access.triggers,
  convertToNotificationUser: (user: User) => ({ user_id: user.id }),
}));
vi.mock('../../../../src/database/middleware', () => ({
  stixLoadById: async (_: unknown, __: unknown, id: string) => {
    if (id === 'case-1') return access.liveCase ? { id: 'x-opencti-case-incident--1', type: 'x-opencti-case-incident', name: 'Phishing wave' } : undefined;
    return { id: 'incident--1', type: 'incident', name: 'Credential phishing' };
  },
}));
vi.mock('../../../../src/database/cache', () => ({ getEntityFromCache: async () => ({}) }));
vi.mock('../../../../src/database/stream/stream-handler', () => ({
  storeNotificationEvent: async (_: unknown, event: (typeof access.stored)[number]) => {
    access.stored.push(event);
  },
}));
vi.mock('../../../../src/database/stix-representative', () => ({ extractStixRepresentative: (stix: { name: string }) => stix.name }));
vi.mock('../../../../src/utils/filtering/filtering-stix/stix-filtering', () => ({
  isStixMatchFilterGroup: async (_: unknown, user: User) => access.matchesFilter.has(user.id),
}));
vi.mock('../../../../src/utils/access', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  isUserInPlatformOrganization: () => true,
  isUserCanAccessStixElement: async (_: unknown, user: User) => access.readsCase.has(user.id),
  isUserCanAccessStoreElement: async (_: unknown, user: User) => access.readsRun.has(user.id),
}));

const { notifyInvestigationRunStatus } = await import('../../../../src/modules/investigationRun/investigationRun-notification');

const context = { source: 'test', otp_mandatory: false, user_inside_platform_organization: true } as never;
const previous = buildRun({ run_status: InvestigationRunStatus.Running, case_id: 'case-1', subject_id: 'incident-1' });
const completed = buildRun({ run_status: InvestigationRunStatus.Completed, case_id: 'case-1', subject_id: 'incident-1' });
const trigger = (id: string, users: User[], eventTypes = ['investigation_completed']) => ({
  users, trigger: { internal_id: id, event_types: eventTypes, filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }), notifiers: [] },
});

describe('Case Autopilot notification delivery', () => {
  beforeEach(() => {
    access.readsCase = new Set(['analyst', 'restricted', 'unmatched']);
    access.readsRun = new Set(['analyst', 'unmatched']);
    access.matchesFilter = new Set(['analyst', 'restricted']);
    access.liveCase = true;
    access.stored = [];
  });

  it('delivers only to recipients who read the case and the run, and whose filters match', async () => {
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }, { id: 'restricted' }, { id: 'unmatched' }])];
    const delivered = await notifyInvestigationRunStatus(context, previous, completed);
    expect(delivered).toBe(1);
    expect(access.stored).toHaveLength(1);
    expect(access.stored[0].notification_id).toBe('trigger-1');
    expect(access.stored[0].targets.map((target) => target.user.user_id)).toEqual(['analyst']);
    expect(access.stored[0].targets[0].type).toBe('investigation_completed');
  });

  it('sends nothing when no recipient may read the run, or no trigger listens to the event', async () => {
    access.readsRun = new Set();
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }, { id: 'restricted' }])];
    expect(await notifyInvestigationRunStatus(context, previous, completed)).toBe(0);
    access.triggers = [trigger('trigger-2', [{ id: 'analyst' }], ['investigation_failed'])];
    expect(await notifyInvestigationRunStatus(context, previous, completed)).toBe(0);
    expect(await notifyInvestigationRunStatus(context, completed, completed)).toBe(0);
    expect(access.stored).toEqual([]);
  });

  it('delivers on the investigated entity while the case exists only in the draft', async () => {
    access.liveCase = false;
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }])];
    expect(await notifyInvestigationRunStatus(context, previous, completed)).toBe(1);
    expect(access.stored[0].targets[0].message).toContain('Credential phishing');
  });
});
