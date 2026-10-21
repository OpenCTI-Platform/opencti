import { beforeEach, describe, expect, it, vi } from 'vitest';
import { InvestigationRunStatus } from '../../../../src/generated/graphql';
import { SOURCE_INACCESSIBLE_CODE } from '../../../../src/modules/investigationRun/investigationRun-types';
import { buildRun } from './investigationRun-fixtures';

type User = { id: string; personal_notifiers?: string[] };
const access = vi.hoisted(() => ({
  readsCase: new Set<string>(),
  readsRun: new Set<string>(),
  matchesFilter: new Set<string>(),
  liveCase: true,
  sourceUnreadable: new Set<string>(),
  liveMarkings: [] as string[],
  unreadableMarkings: new Map<string, Set<string>>(),
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
  isUserCanAccessStoreElement: async (_: unknown, user: User, run: { 'object-marking'?: string[] }) => access.readsRun.has(user.id)
    && !(run['object-marking'] ?? []).some((marking) => access.unreadableMarkings.get(user.id)?.has(marking)),
}));

const { notifyInvestigationRunStatus } = await import('../../../../src/modules/investigationRun/investigationRun-notification');

const context = { source: 'test', otp_mandatory: false, user_inside_platform_organization: true } as never;
const previous = buildRun({ run_status: InvestigationRunStatus.Running, case_id: 'case-1', subject_id: 'incident-1' });
const completed = buildRun({ run_status: InvestigationRunStatus.Completed, case_id: 'case-1', subject_id: 'incident-1' });
// The run as served to a recipient: findings withheld when a source is unreadable to them, live markings added.
const serve = async (_: unknown, user: User, run: typeof completed) => (access.sourceUnreadable.has(user.id)
  ? { ...run, end_reason_code: SOURCE_INACCESSIBLE_CODE }
  : { ...run, 'object-marking': [...(run['object-marking'] ?? []), ...access.liveMarkings] }) as typeof completed;
const trigger = (id: string, users: User[], eventTypes = ['investigation_completed']) => ({
  users, trigger: { internal_id: id, event_types: eventTypes, filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }), notifiers: [] },
});

describe('Case Autopilot notification delivery', () => {
  beforeEach(() => {
    access.readsCase = new Set(['analyst', 'restricted', 'unmatched']);
    access.readsRun = new Set(['analyst', 'unmatched']);
    access.matchesFilter = new Set(['analyst', 'restricted']);
    access.liveCase = true;
    access.sourceUnreadable = new Set();
    access.liveMarkings = [];
    access.unreadableMarkings = new Map();
    access.stored = [];
  });

  it('skips a recipient who can no longer read a source the run cites', async () => {
    access.readsRun = new Set(['analyst', 'restricted']);
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }, { id: 'restricted' }])];
    access.sourceUnreadable = new Set(['restricted']);
    expect(await notifyInvestigationRunStatus(context, previous, completed, serve)).toBe(1);
    expect(access.stored[0].targets.map((target) => target.user.user_id)).toEqual(['analyst']);
  });

  it('checks the live markings of the sources, not only the markings stored on the run', async () => {
    access.readsRun = new Set(['analyst', 'restricted']);
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }, { id: 'restricted' }])];
    access.liveMarkings = ['marking-tlp-red'];
    access.unreadableMarkings = new Map([['restricted', new Set(['marking-tlp-red'])]]);
    expect(await notifyInvestigationRunStatus(context, previous, completed, serve)).toBe(1);
    expect(access.stored[0].targets.map((target) => target.user.user_id)).toEqual(['analyst']);
  });

  it('delivers only to recipients who read the case and the run, and whose filters match', async () => {
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }, { id: 'restricted' }, { id: 'unmatched' }])];
    const delivered = await notifyInvestigationRunStatus(context, previous, completed, serve);
    expect(delivered).toBe(1);
    expect(access.stored).toHaveLength(1);
    expect(access.stored[0].notification_id).toBe('trigger-1');
    expect(access.stored[0].targets.map((target) => target.user.user_id)).toEqual(['analyst']);
    expect(access.stored[0].targets[0].type).toBe('investigation_completed');
  });

  it('sends nothing when no recipient may read the run, or no trigger listens to the event', async () => {
    access.readsRun = new Set();
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }, { id: 'restricted' }])];
    expect(await notifyInvestigationRunStatus(context, previous, completed, serve)).toBe(0);
    access.triggers = [trigger('trigger-2', [{ id: 'analyst' }], ['investigation_failed'])];
    expect(await notifyInvestigationRunStatus(context, previous, completed, serve)).toBe(0);
    expect(await notifyInvestigationRunStatus(context, completed, completed, serve)).toBe(0);
    expect(access.stored).toEqual([]);
  });

  it('delivers on the investigated entity while the case exists only in the draft', async () => {
    access.liveCase = false;
    access.triggers = [trigger('trigger-1', [{ id: 'analyst' }])];
    expect(await notifyInvestigationRunStatus(context, previous, completed, serve)).toBe(1);
    expect(access.stored[0].targets[0].message).toContain('Credential phishing');
  });
});
