import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { executeProposalAction } from '../../../../src/modules/curation/curation-apply';
import { deleteElementById } from '../../../../src/database/middleware';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import type { BasicStoreEntityCurationProposal, CurationSettings } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  deleteElementById: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(async () => []),
  fullEntitiesList: vi.fn(async () => []),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
const settings = {} as CurationSettings;
const KEEP = { payload: { keep_actor_id: 'actor-keep' } };

const relation = (id: string) => ({ internal_id: id, standard_id: `relationship--${id}`, entity_type: 'attributed-to' });

const conflict = (overrides: Partial<BasicStoreEntityCurationProposal> = {}) => ({
  internal_id: 'proposal-id',
  proposal_kind: 'contradiction',
  recommended_action: 'resolve_attribution',
  subject_ids: ['campaign-id', 'actor-keep', 'actor-other'],
  target_id: 'campaign-id',
  action_payload: {
    attributed_id: 'campaign-id',
    relationships: [{ actor_id: 'actor-keep', relationship_id: 'rel-keep' }, { actor_id: 'actor-other', relationship_id: 'rel-other' }],
  },
  ...overrides,
} as unknown as BasicStoreEntityCurationProposal);

const remainingAttributions = (...ids: string[]) => vi.mocked(internalFindByIds).mockResolvedValue(ids.map(relation) as never);

describe('resolving an attribution conflict checks the conflict again', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('removes the other attribution while both are there', async () => {
    remainingAttributions('rel-keep', 'rel-other');
    const result = await executeProposalAction(context, user, conflict(), settings, KEEP);
    expect(deleteElementById).toHaveBeenCalledWith(context, user, 'rel-other', 'attributed-to');
    expect(result.appliedPatch?.deleted_ids).toEqual(['rel-other']);
  });

  it('refuses when the attribution to keep was deleted, so the last one left is never removed', async () => {
    remainingAttributions('rel-other');
    await expect(executeProposalAction(context, user, conflict(), settings, KEEP)).rejects.toThrow('The attribution to keep was deleted');
    expect(deleteElementById).not.toHaveBeenCalled();
  });

  it('refuses when only the attribution to keep remains: the contradiction is resolved', async () => {
    remainingAttributions('rel-keep');
    await expect(executeProposalAction(context, user, conflict(), settings, KEEP)).rejects.toThrow('so the contradiction is resolved');
    expect(deleteElementById).not.toHaveBeenCalled();
  });

  it('lets a retry complete once the attempt that started it removed the other attribution', async () => {
    remainingAttributions('rel-keep');
    const retry = conflict({ application_started_at: '2026-10-07T03:00:00.000Z' });
    const result = await executeProposalAction(context, user, retry, settings, KEEP);
    expect(deleteElementById).not.toHaveBeenCalled();
    expect(result.appliedPatch?.deleted_ids).toEqual([]);
  });
});
