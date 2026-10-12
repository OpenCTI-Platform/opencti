import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { markProposalReverted } from '../../../../src/modules/curation/curation-proposals';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { patchAttribute } from '../../../../src/database/middleware';
import { addCurationProposalRevertedCount } from '../../../../src/manager/telemetryManager';
import { PROPOSAL_STATUS_ACCEPTED, PROPOSAL_STATUS_REVERTED } from '../../../../src/modules/curation/curation-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  patchAttribute: vi.fn(async () => ({ element: { internal_id: 'proposal-id', proposal_status: 'reverted' } })),
}));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addCurationProposalRevertedCount: vi.fn(),
}));

const context = {} as AuthContext;

describe('closing a proposal as reverted', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('counts the reversion when it closes an applied proposal', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ internal_id: 'proposal-id', proposal_status: PROPOSAL_STATUS_ACCEPTED } as never);
    await expect(markProposalReverted(context, 'proposal-id')).resolves.toEqual(expect.objectContaining({ proposal_status: PROPOSAL_STATUS_REVERTED }));
    expect(patchAttribute).toHaveBeenCalledTimes(1);
    expect(addCurationProposalRevertedCount).toHaveBeenCalledTimes(1);
  });

  // The revert of a merge proposal unmerges its record, which closes the proposal first: the revert then counts nothing.
  it('counts nothing for a proposal an unmerge already closed', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ internal_id: 'proposal-id', proposal_status: PROPOSAL_STATUS_REVERTED } as never);
    await expect(markProposalReverted(context, 'proposal-id')).resolves.toEqual(expect.objectContaining({ proposal_status: PROPOSAL_STATUS_REVERTED }));
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(addCurationProposalRevertedCount).not.toHaveBeenCalled();
  });
});
