import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { findProposalById } from '../../../../src/modules/curation/curation-domain';
import { internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
  storeLoadById: vi.fn(),
}));

const context = {} as AuthContext;
const analyst = { id: 'analyst-id', capabilities: [{ name: 'KNOWLEDGE' }] } as unknown as AuthUser;
const attributionConflict = {
  internal_id: 'proposal-id',
  entity_type: 'CurationProposal',
  subject_ids: ['malware-id'],
  action_payload: JSON.stringify({ relationships: [{ relationship_id: 'attribution-a' }, { relationship_id: 'attribution-b' }] }),
};

describe('reading a proposal before its restrictions are refreshed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(storeLoadById).mockResolvedValue(attributionConflict as never);
  });

  it('hides a proposal one of whose relationships the user can no longer read', async () => {
    vi.mocked(internalFindByIds)
      .mockResolvedValueOnce([{ internal_id: 'malware-id' }, { internal_id: 'attribution-a' }] as never)
      .mockResolvedValueOnce([{ internal_id: 'attribution-b' }] as never);
    expect(await findProposalById(context, analyst, 'proposal-id')).toBeUndefined();
    expect(vi.mocked(internalFindByIds).mock.calls[0][2]).toEqual(['malware-id', 'attribution-a', 'attribution-b']);
  });

  it('shows it when a relationship it names was deleted', async () => {
    vi.mocked(internalFindByIds)
      .mockResolvedValueOnce([{ internal_id: 'malware-id' }, { internal_id: 'attribution-a' }] as never)
      .mockResolvedValueOnce([] as never);
    expect(await findProposalById(context, analyst, 'proposal-id')).toEqual(attributionConflict);
  });
});
