import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UserMergeHandlerContext } from '../../../../src/modules/userMerge/userMerge-handler';

const { elRawCount } = vi.hoisted(() => ({ elRawCount: vi.fn(async (_query: any): Promise<number> => 0) }));

vi.mock('../../../../src/database/engine', () => ({ elRawCount }));

const { isExposureWidening, userMergeExposureDiff, userMergePublicSharingHandler } = await import('../../../../src/modules/userMerge/userMerge-publicSharingHandler');
const { userMergeProjectRights } = await import('../../../../src/modules/userMerge/userMerge-rights');
const { UserMergeRightsStrategy } = await import('../../../../src/modules/userMerge/userMerge-types');

const EMPTY = { markings: [], organizations: [], capabilities: [], groups: [] };
const source = { ...EMPTY, markings: ['marking-red'], organizations: ['organization-filigran'] };
const target = { ...EMPTY, markings: ['marking-green'] };

describe('User merge public sharing exposure', () => {
  it('should report what a transferred endpoint gains and loses under the strict strategy', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Strict);
    const diff = userMergeExposureDiff(source, projected);
    expect(diff.addedMarkings).toEqual(['marking-green']);
    expect(diff.removedMarkings).toEqual(['marking-red']);
    expect(diff.removedOrganizations).toEqual(['organization-filigran']);
  });

  it('should never report a loss on a transferred endpoint under the union strategy', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Union);
    const diff = userMergeExposureDiff(source, projected);
    expect(diff.removedMarkings).toEqual([]);
    expect(diff.addedMarkings).toEqual(['marking-green']);
  });

  it('should leave the endpoints already served with the target untouched under the strict strategy', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Strict);
    const diff = userMergeExposureDiff(target, projected);
    expect(diff).toEqual({
      addedMarkings: [],
      removedMarkings: [],
      addedOrganizations: [],
      removedOrganizations: [],
      addedCapabilities: [],
      removedCapabilities: [],
      addedGroups: [],
      removedGroups: [],
      gainedServiceAccount: false,
      lostServiceAccount: false,
    });
  });

  it('should widen the endpoints already served with the target under the union strategy', () => {
    const projected = userMergeProjectRights(source, target, UserMergeRightsStrategy.Union);
    const diff = userMergeExposureDiff(target, projected);
    expect(diff.addedMarkings).toEqual(['marking-red']);
    expect(diff.addedOrganizations).toEqual(['organization-filigran']);
    expect(isExposureWidening(diff)).toBe(true);
  });

  it('should consider an organization-only change as a widening', () => {
    const diff = userMergeExposureDiff(EMPTY, { ...EMPTY, organizations: ['organization-filigran'] });
    expect(isExposureWidening(diff)).toBe(true);
  });

  it('should consider a capability gained as a widening', () => {
    const diff = userMergeExposureDiff(EMPTY, { ...EMPTY, capabilities: ['BYPASS'] });
    expect(diff.addedCapabilities).toEqual(['BYPASS']);
    expect(isExposureWidening(diff)).toBe(true);
  });

  it('should consider a group gained as a widening', () => {
    const diff = userMergeExposureDiff(EMPTY, { ...EMPTY, groups: ['group-analysts'] });
    expect(diff.addedGroups).toEqual(['group-analysts']);
    expect(isExposureWidening(diff)).toBe(true);
  });

  it('should consider a service account gained as a widening', () => {
    const diff = userMergeExposureDiff(EMPTY, EMPTY, { gained: true, lost: false });
    expect(isExposureWidening(diff)).toBe(true);
  });

  it('should not consider a service account lost as a widening', () => {
    const diff = userMergeExposureDiff(EMPTY, EMPTY, { gained: false, lost: true });
    expect(isExposureWidening(diff)).toBe(false);
  });

  it('should not consider a narrower exposure as a widening', () => {
    const diff = userMergeExposureDiff({ ...EMPTY, markings: ['marking-red'], organizations: ['organization-filigran'], capabilities: ['KNOWLEDGE'], groups: ['group-analysts'] }, EMPTY);
    expect(isExposureWidening(diff)).toBe(false);
  });
});

const names = (query: any, userId: string) => query.bool.must.some((term: any) => Object.values(term.term ?? {})[0] === userId);

const asksForPublic = (query: any) => query.bool.must.some((term: any) => Object.values(term.term ?? {})[0] === true);

/** One endpoint of the given user, anonymous or not. */
const oneEndpointOf = (userId: string, isPublic: boolean) => async ({ body }: any) => {
  if (!names(body.query, userId)) {
    return 0;
  }
  return asksForPublic(body.query) && !isPublic ? 0 : 1;
};

const sharingContext = (
  rights: UserMergeHandlerContext['rights'],
  individuals: { source?: string; target?: string } = {},
  serviceAccounts: { source?: boolean; target?: boolean } = {},
) => ({
  sourceId: 'source-id',
  targetId: 'target-id',
  sourceUser: { internal_id: 'source-id', individual_id: individuals.source, user_service_account: serviceAccounts.source } as never,
  targetUser: { internal_id: 'target-id', individual_id: individuals.target, user_service_account: serviceAccounts.target } as never,
  rights,
} as unknown as UserMergeHandlerContext);

describe('User merge public sharing plan', () => {
  beforeEach(() => {
    elRawCount.mockReset();
  });

  it('should plan the rewrite of a private endpoint without reporting an exposure', async () => {
    elRawCount.mockImplementation(oneEndpointOf('source-id', false));
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY,
      target: { ...EMPTY, markings: ['marking-red'] },
      projected: { ...EMPTY, markings: ['marking-red'] },
      labels: {},
    }));
    expect(plan.changes.filter((change) => change.count > 0)).toHaveLength(3);
    expect(plan.alerts).toEqual([]);
  });

  it('should block on an anonymous endpoint whose exposure widens', async () => {
    elRawCount.mockImplementation(oneEndpointOf('source-id', true));
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY,
      target: { ...EMPTY, markings: ['marking-red'] },
      projected: { ...EMPTY, markings: ['marking-red'] },
      labels: { 'marking-red': 'TLP:RED' },
    }));
    expect(plan.alerts.filter((alert) => alert.blocking === true)).toHaveLength(3);
    expect(plan.alerts[0].message).toContain('TLP:RED');
  });

  it('should state the access channels the rights sets do not describe', async () => {
    elRawCount.mockImplementation(oneEndpointOf('target-id', true));
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY, target: EMPTY, projected: EMPTY, labels: {},
    }, { source: 'individual-id' }));
    expect(plan.alerts).toHaveLength(3);
    expect(plan.alerts[0].blocking).toBeUndefined();
    expect(plan.alerts[0].message).toContain('authorized member');
    expect(plan.alerts[0].message).toContain('individual');
  });

  it('should name the counterpart user on each side of the transfer', async () => {
    elRawCount.mockImplementation(async () => 1);
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY, target: EMPTY, projected: EMPTY, labels: {},
    }, { target: 'target-individual-id' }));
    const transferred = plan.alerts.filter((alert) => alert.message.includes('transferred to the target user'));
    const already = plan.alerts.filter((alert) => alert.message.includes('already configured with the target user'));
    expect(transferred).toHaveLength(3);
    expect(already).toHaveLength(3);
    expect(transferred[0].message).toContain('the target user is an authorized member of');
    expect(transferred[0].message).toContain('what its individual created');
    expect(already[0].message).toContain('the source user is an authorized member of');
    expect(already[0].message).not.toContain('individual');
  });

  it('should block on an anonymous endpoint moving to a service account', async () => {
    elRawCount.mockImplementation(oneEndpointOf('source-id', true));
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY, target: EMPTY, projected: EMPTY, labels: {},
    }, {}, { target: true }));
    const blocking = plan.alerts.filter((alert) => alert.blocking === true);
    expect(blocking).toHaveLength(3);
    expect(blocking[0].message).toContain('service account gained');
  });

  it('should report the loss of a service account without blocking', async () => {
    elRawCount.mockImplementation(oneEndpointOf('source-id', true));
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY, target: EMPTY, projected: EMPTY, labels: {},
    }, {}, { source: true }));
    const exposure = plan.alerts.filter((alert) => alert.message.includes('service account lost'));
    expect(exposure).toHaveLength(3);
    expect(exposure[0].blocking).toBe(false);
  });

  it('should not report a service account the source already was', async () => {
    elRawCount.mockImplementation(oneEndpointOf('source-id', true));
    const plan = await userMergePublicSharingHandler.compute(sharingContext({
      source: EMPTY, target: EMPTY, projected: EMPTY, labels: {},
    }, {}, { source: true, target: true }));
    expect(plan.alerts.filter((alert) => alert.blocking === true)).toEqual([]);
  });
});
