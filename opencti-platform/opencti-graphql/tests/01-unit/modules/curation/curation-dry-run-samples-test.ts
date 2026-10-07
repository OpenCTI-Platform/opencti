import { beforeEach, describe, expect, it, vi } from 'vitest';
import curationResolvers from '../../../../src/modules/curation/curation-resolvers';
import { findProposalById } from '../../../../src/modules/curation/curation-domain';
import { KNOWLEDGE, SETTINGS_SETCUSTOMIZATION } from '../../../../src/utils/access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/modules/curation/curation-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-domain')>()),
  findProposalById: vi.fn(async (_context: unknown, _user: unknown, id: string) => ({ internal_id: id })),
}));

const userWith = (...capabilities: string[]) => ({ id: 'user-id', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;
const sampleProposals = (user: AuthUser) => (curationResolvers.CurationPolicyDryRun as any)
  .sample_proposals({ sample_proposal_ids: ['proposal-1', 'proposal-2'] }, {}, { user } as AuthContext);

describe('curation policy dry run samples', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('resolves the sample proposals for a policy manager with Access knowledge', async () => {
    expect(await sampleProposals(userWith(SETTINGS_SETCUSTOMIZATION, KNOWLEDGE))).toEqual([{ internal_id: 'proposal-1' }, { internal_id: 'proposal-2' }]);
  });

  it('gives a policy manager without Access knowledge the counts only, never the proposals', async () => {
    expect(await sampleProposals(userWith(SETTINGS_SETCUSTOMIZATION))).toEqual([]);
    expect(findProposalById).not.toHaveBeenCalled();
  });
});
