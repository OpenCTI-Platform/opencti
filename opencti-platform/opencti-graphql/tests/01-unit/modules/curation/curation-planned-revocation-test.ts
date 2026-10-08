import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { type ApplyResult, checkPlannedRevocation } from '../../../../src/modules/curation/curation-apply';
import { pageRelationsConnection } from '../../../../src/database/middleware-loader';
import { storeLoadByIdWithRefs, updateAttribute } from '../../../../src/database/middleware';
import { ACTION_REVOKE, EVIDENCE_STALENESS, PROPOSAL_KIND_CONTRADICTION, PROPOSAL_KIND_STALE } from '../../../../src/modules/curation/curation-types';
import type { BasicStoreEntityCurationProposal } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  pageRelationsConnection: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  storeLoadByIdWithRefs: vi.fn(),
  updateAttribute: vi.fn(async () => ({ element: {} })),
}));
vi.mock('../../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(async () => ({ unlock: vi.fn() })),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id', capabilities: [{ name: 'BYPASS' }], effective_confidence_level: { max_confidence: 100, overrides: [] } } as unknown as AuthUser;
const proposal = {
  internal_id: 'proposal-id',
  proposal_kind: PROPOSAL_KIND_STALE,
  proposal_status: 'open',
  recommended_action: ACTION_REVOKE,
  subject_ids: ['malware-id'],
  curation_evidence: [{ evidence_type: EVIDENCE_STALENESS, details: JSON.stringify({ months: 12 }) }],
} as unknown as BasicStoreEntityCurationProposal;
const revocation: ApplyResult = {
  appliedPatch: {
    operations: [{ element_id: 'malware-id', entity_type: 'Malware', key: 'revoked', previous: false, value: true }],
    applied_at: '2026-10-07T08:00:00.000Z',
  },
  mergeRecordId: null,
};
const relationships = (count: number) => ({ edges: Array.from({ length: count }, () => ({ node: {} })) });

describe('curation planned revocation found by a retry', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue({ internal_id: 'malware-id', entity_type: 'Malware', revoked: true } as never);
  });

  it('puts back an entity that gained a relationship and refuses the acceptance', async () => {
    vi.mocked(pageRelationsConnection).mockResolvedValue(relationships(1) as never);
    await expect(checkPlannedRevocation(context, user, proposal, revocation)).rejects.toThrow('not stale any more');
    expect(updateAttribute).toHaveBeenCalledWith(context, user, 'malware-id', 'Malware', [{ key: 'revoked', value: [false] }], expect.anything());
  });

  it('leaves the revocation of an entity still stale to be recorded', async () => {
    vi.mocked(pageRelationsConnection).mockResolvedValue(relationships(0) as never);
    await expect(checkPlannedRevocation(context, user, proposal, revocation)).resolves.toBeUndefined();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('leaves the plan to the next retry when the entity cannot be put back', async () => {
    vi.mocked(pageRelationsConnection).mockResolvedValue(relationships(1) as never);
    vi.mocked(updateAttribute).mockRejectedValueOnce(new Error('search engine unavailable'));
    await expect(checkPlannedRevocation(context, user, proposal, revocation)).rejects.toThrow('search engine unavailable');
  });

  it('checks nothing for a proposal that does not revoke a stale entity', async () => {
    const contradiction = { ...proposal, proposal_kind: PROPOSAL_KIND_CONTRADICTION } as BasicStoreEntityCurationProposal;
    await expect(checkPlannedRevocation(context, user, contradiction, revocation)).resolves.toBeUndefined();
    expect(pageRelationsConnection).not.toHaveBeenCalled();
  });
});
