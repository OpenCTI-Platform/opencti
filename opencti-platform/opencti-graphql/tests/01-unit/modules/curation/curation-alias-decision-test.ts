import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { GraphQLError } from 'graphql';
import '../../../../src/modules/index';
import { executeProposalAction } from '../../../../src/modules/curation/curation-apply';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { storeLoadByIdWithRefs, updateAttribute } from '../../../../src/database/middleware';
import { ACTION_MERGE, DECISION_ALIAS, PROPOSAL_KIND_MERGE } from '../../../../src/modules/curation/curation-types';
import type { BasicStoreEntityCurationProposal, CurationSettings } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  storeLoadByIdWithRefs: vi.fn(),
  updateAttribute: vi.fn(async () => ({ element: {} })),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id', capabilities: [{ name: 'BYPASS' }], effective_confidence_level: { max_confidence: 100, overrides: [] } } as unknown as AuthUser;
const proposal = {
  internal_id: 'proposal-id',
  proposal_kind: PROPOSAL_KIND_MERGE,
  proposal_status: 'open',
  recommended_action: ACTION_MERGE,
  subject_ids: ['first-id', 'second-id'],
  subject_names: ['APT28', 'Fancy Bear'],
  target_id: 'first-id',
} as unknown as BasicStoreEntityCurationProposal;

describe('curation alias decision on a duplicate proposal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue({ internal_id: 'first-id', entity_type: 'Intrusion-Set', name: 'APT28', aliases: [] } as never);
  });

  it('refuses names that still belong to other entities without naming those entities', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue([{ internal_id: 'hidden-owner-id', entity_type: 'Intrusion-Set' }] as never);
    const error = await executeProposalAction(context, user, proposal, {} as CurationSettings, { decision: DECISION_ALIAS })
      .catch((caught: GraphQLError) => caught) as GraphQLError;
    expect(error.message).toContain('These names still belong to other entities');
    expect(error.extensions.data).toMatchObject({ proposal_id: 'proposal-id' });
    expect(JSON.stringify(error.extensions)).not.toContain('hidden-owner-id');
    expect(updateAttribute).not.toHaveBeenCalled();
  });
});
