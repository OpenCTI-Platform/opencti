import { describe, expect, it } from 'vitest';
import { alignSummaryEnd, landscapeDiffCacheKey, userAccessFingerprint } from '../../../../src/modules/timeMachine/landscapeDiff-domain';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const buildUser = (overrides: Partial<Record<string, unknown>> = {}) => ({
  id: 'user-1',
  capabilities: [{ name: 'KNOWLEDGE' }, { name: 'EXPLORE' }],
  allowed_marking: [{ internal_id: 'marking-green' }, { internal_id: 'marking-white' }],
  organizations: [{ internal_id: 'organization-1' }],
  groups: [{ internal_id: 'group-1' }],
  ...overrides,
} as unknown as AuthUser);

const context = { user_inside_platform_organization: true } as unknown as AuthContext;
const input = { from: '2026-07-01T00:00:00.000Z', to: '2026-10-01T00:00:00.000Z', group_by: 'entity_type' };
const scope = { filters: null, entityTypes: ['Intrusion-Set'] };

describe('Landscape diff cache and rights', () => {
  it('should give the same fingerprint to the same rights whatever their order', () => {
    const reordered = buildUser({
      capabilities: [{ name: 'EXPLORE' }, { name: 'KNOWLEDGE' }],
      allowed_marking: [{ internal_id: 'marking-white' }, { internal_id: 'marking-green' }],
    });
    expect(userAccessFingerprint(context, reordered)).toEqual(userAccessFingerprint(context, buildUser()));
  });

  it('should change the fingerprint when the rights of the user change', () => {
    const reference = userAccessFingerprint(context, buildUser());
    expect(userAccessFingerprint(context, buildUser({ allowed_marking: [{ internal_id: 'marking-green' }] }))).not.toEqual(reference);
    expect(userAccessFingerprint(context, buildUser({ capabilities: [{ name: 'KNOWLEDGE' }] }))).not.toEqual(reference);
    expect(userAccessFingerprint(context, buildUser({ organizations: [] }))).not.toEqual(reference);
    expect(userAccessFingerprint(context, buildUser({ groups: [{ internal_id: 'group-2' }] }))).not.toEqual(reference);
    const outsideOrganization = { user_inside_platform_organization: false } as unknown as AuthContext;
    expect(userAccessFingerprint(outsideOrganization, buildUser())).not.toEqual(reference);
    const inDraft = { user_inside_platform_organization: true, draft_context: 'draft-1' } as unknown as AuthContext;
    expect(userAccessFingerprint(inDraft, buildUser())).not.toEqual(reference);
  });

  it('should never share a cached landscape diff across users or rights', () => {
    const fingerprint = userAccessFingerprint(context, buildUser());
    const key = landscapeDiffCacheKey('user-1', fingerprint, input, scope);
    expect(landscapeDiffCacheKey('user-1', fingerprint, input, scope)).toEqual(key);
    expect(landscapeDiffCacheKey('user-2', fingerprint, input, scope)).not.toEqual(key);
    expect(landscapeDiffCacheKey('user-1', userAccessFingerprint(context, buildUser({ groups: [] })), input, scope)).not.toEqual(key);
    expect(landscapeDiffCacheKey('user-1', fingerprint, { ...input, group_by: 'tactic' }, scope)).not.toEqual(key);
  });

  it('should separate the results computed in a draft from the main knowledge', () => {
    const main = userAccessFingerprint(context, buildUser());
    expect(userAccessFingerprint(context, buildUser({ draft_context: 'draft-1' }))).not.toEqual(main);
    expect(userAccessFingerprint({ ...context, draft_context: 'draft-1' } as AuthContext, buildUser())).not.toEqual(main);
  });

  it('should align the end of a widget period on the next minute without excluding the requested period', () => {
    expect(alignSummaryEnd('2026-10-03T12:00:00.000Z')).toEqual('2026-10-03T12:00:00.000Z');
    expect(alignSummaryEnd('2026-10-03T12:00:00.001Z')).toEqual('2026-10-03T12:01:00.000Z');
    expect(alignSummaryEnd('2026-10-03T12:00:45.000Z')).toEqual('2026-10-03T12:01:00.000Z');
    expect(alignSummaryEnd('2026-10-03T23:59:30.000Z')).toEqual('2026-10-04T00:00:00.000Z');
  });
});
