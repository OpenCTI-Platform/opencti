import { describe, expect, it } from 'vitest';
import type { AuthUser } from '../../../../src/types/user';
import { canUserApplyProposal } from '../../../../src/modules/curation/curation-access';

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

  it('lets a bypass user apply anything', () => {
    (['merge', 'unmerge', 'resolve_attribution', 'fix_dates'] as const).forEach((action) => {
      expect(canUserApplyProposal(BYPASS, { recommended_action: action })).toBe(true);
    });
  });
});
