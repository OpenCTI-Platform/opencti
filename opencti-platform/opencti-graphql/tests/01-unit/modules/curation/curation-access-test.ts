import { describe, expect, it } from 'vitest';
import type { AuthUser } from '../../../../src/types/user';
import { canUserApplyProposal, effectiveProposalAction } from '../../../../src/modules/curation/curation-access';

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
});
