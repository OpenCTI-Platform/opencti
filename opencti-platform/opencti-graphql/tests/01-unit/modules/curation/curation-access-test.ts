import { describe, expect, it } from 'vitest';
import type { AuthUser } from '../../../../src/types/user';
import { canUserApplyPolicy, canUserApplyProposal, canUserRevertProposal, effectiveProposalAction, revertedProposalAction } from '../../../../src/modules/curation/curation-access';
import { intersectGrantedOrganizations } from '../../../../src/modules/curation/curation-proposals';

const userWith = (...capabilities: string[]) => ({ id: 'user', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;

const UPDATE = userWith('KNOWLEDGE_KNUPDATE');
const MERGE = userWith('KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNMERGE');
const DELETE = userWith('KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNDELETE');
const READ = userWith('KNOWLEDGE');
const BYPASS = userWith('BYPASS');

describe('curation apply access', () => {
  it('requires the update capability for every proposal', () => {
    expect(canUserApplyProposal(READ, { recommended_action: 'add_aliases' })).toBe(false);
    expect(canUserApplyProposal(UPDATE, { recommended_action: 'add_aliases' })).toBe(true);
  });

  it('requires the merge capability to apply a merge or an unmerge', () => {
    (['merge', 'unmerge'] as const).forEach((action) => {
      expect(canUserApplyProposal(UPDATE, { recommended_action: action })).toBe(false);
      expect(canUserApplyProposal(MERGE, { recommended_action: action })).toBe(true);
    });
  });

  it('requires the delete capability to resolve an attribution conflict', () => {
    expect(canUserApplyProposal(MERGE, { recommended_action: 'resolve_attribution' })).toBe(false);
    expect(canUserApplyProposal(DELETE, { recommended_action: 'resolve_attribution' })).toBe(true);
  });

  it('reverts what was applied, whatever the proposal recommended', () => {
    // An alias proposal applied as a merge has a merge record: its revert is an unmerge.
    expect(revertedProposalAction({ recommended_action: 'add_aliases', merge_record_id: 'record' })).toBe('unmerge');
    expect(canUserRevertProposal(UPDATE, { recommended_action: 'add_aliases', merge_record_id: 'record' })).toBe(false);
    expect(canUserRevertProposal(MERGE, { recommended_action: 'add_aliases', merge_record_id: 'record' })).toBe(true);
    // A merge proposal applied as an alias addition has no merge record: reverting it only needs the update capability.
    expect(revertedProposalAction({ recommended_action: 'merge', merge_record_id: null })).toBe('add_aliases');
    expect(canUserRevertProposal(UPDATE, { recommended_action: 'merge', merge_record_id: null })).toBe(true);
    expect(canUserRevertProposal(MERGE, { recommended_action: 'resolve_attribution', merge_record_id: null })).toBe(false);
    expect(canUserRevertProposal(DELETE, { recommended_action: 'resolve_attribution', merge_record_id: null })).toBe(true);
  });

  it('runs the action an adjudication decision states on a duplicate proposal', () => {
    expect(effectiveProposalAction({ recommended_action: 'add_aliases' }, 'merge')).toBe('merge');
    expect(effectiveProposalAction({ recommended_action: 'merge' }, 'alias')).toBe('add_aliases');
    expect(effectiveProposalAction({ recommended_action: 'merge' }, 'merge')).toBe('merge');
    expect(effectiveProposalAction({ recommended_action: 'add_aliases' }, null)).toBe('add_aliases');
    // Other kinds take no decision: their action never changes.
    expect(effectiveProposalAction({ recommended_action: 'fix_dates' }, 'merge')).toBe('fix_dates');
  });

  it('checks the capability of the action the decision runs', () => {
    expect(canUserApplyProposal(UPDATE, { recommended_action: 'add_aliases' }, 'merge')).toBe(false);
    expect(canUserApplyProposal(MERGE, { recommended_action: 'add_aliases' }, 'merge')).toBe(true);
    expect(canUserApplyProposal(UPDATE, { recommended_action: 'merge' }, 'alias')).toBe(true);
  });

  it('lets a bypass user apply anything', () => {
    (['merge', 'unmerge', 'resolve_attribution', 'fix_dates'] as const).forEach((action) => {
      expect(canUserApplyProposal(BYPASS, { recommended_action: action })).toBe(true);
    });
  });

  it('applies in the name of a policy only with the right to manage policies', () => {
    expect(canUserApplyPolicy(MERGE)).toBe(false);
    expect(canUserApplyPolicy(DELETE)).toBe(false);
    expect(canUserApplyPolicy(userWith('KNOWLEDGE_KNUPDATE', 'SETTINGS_SETCUSTOMIZATION'))).toBe(true);
    // The curation manager runs scheduled policies as a bypass user.
    expect(canUserApplyPolicy(BYPASS)).toBe(true);
  });
});

describe('curation organization restrictions', () => {
  it('keeps only the organizations every restricted element is shared with', () => {
    expect(intersectGrantedOrganizations([['org-a', 'org-b'], ['org-b', 'org-c']])).toStrictEqual(['org-b']);
    expect(intersectGrantedOrganizations([['org-a', 'org-a'], ['org-a']])).toStrictEqual(['org-a']);
  });

  it('ignores the elements shared with no organization', () => {
    expect(intersectGrantedOrganizations([['org-a'], []])).toStrictEqual(['org-a']);
    expect(intersectGrantedOrganizations([[], []], 'platform-org')).toStrictEqual([]);
  });

  it('leaves only the platform organization when the restricted elements share none', () => {
    expect(intersectGrantedOrganizations([['org-a'], ['org-b']], 'platform-org')).toStrictEqual(['platform-org']);
    expect(intersectGrantedOrganizations([['org-a'], ['org-b']])).toStrictEqual([]);
  });
});
