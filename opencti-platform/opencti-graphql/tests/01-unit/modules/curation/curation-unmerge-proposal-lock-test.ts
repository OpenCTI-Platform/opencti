import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { unmergeFromRecord } from '../../../../src/modules/curation/curation-merge-record';
import { withProposalTransitionLock } from '../../../../src/modules/curation/curation-locks';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { lockResources } from '../../../../src/lock/master-lock';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/lock/master-lock', () => ({
  lockResources: vi.fn(async () => {
    throw new Error('entity locks reached');
  }),
}));
vi.mock('../../../../src/modules/curation/curation-locks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-locks')>()),
  withProposalTransitionLock: vi.fn(async (_id: string, fn: () => Promise<unknown>) => fn()),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
const record = (proposalId: string | null) => ({
  internal_id: 'record-id',
  entity_type: 'MergeRecord',
  merge_status: 'active',
  reversible_until: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
  irreversible_reason: null,
  proposal_id: proposalId,
  merge_target_id: 'target-id',
  merge_source_ids: ['source-id'],
  unmerge_pending_source_ids: [],
  merge_snapshot: {
    target: { internal_id: 'target-id', standard_id: 'malware--target', entity_type: 'Malware', attributes: {}, refs: {} },
    sources: [{ internal_id: 'source-id', standard_id: 'malware--source', entity_type: 'Malware', attributes: {}, refs: {}, redirected: [], recreatable: [], moved_file_ids: [], reverted_at: null }],
  },
});

describe('curation unmerge of a record linked to a proposal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('runs under the lock of the proposal, taken before the entity locks', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(record('proposal-id') as never);
    await expect(unmergeFromRecord(context, user, 'record-id')).rejects.toThrow('entity locks reached');
    expect(withProposalTransitionLock).toHaveBeenCalledWith('proposal-id', expect.any(Function));
    expect(vi.mocked(withProposalTransitionLock).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(lockResources).mock.invocationCallOrder[0]);
  });

  it('does not take the lock again for the revert of that proposal, which holds it', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(record('proposal-id') as never);
    await expect(unmergeFromRecord(context, user, 'record-id', null, { lockedProposalId: 'proposal-id' })).rejects.toThrow('entity locks reached');
    expect(withProposalTransitionLock).not.toHaveBeenCalled();
    expect(lockResources).toHaveBeenCalled();
  });

  it('takes no proposal lock for a merge no proposal applied', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(record(null) as never);
    await expect(unmergeFromRecord(context, user, 'record-id')).rejects.toThrow('entity locks reached');
    expect(withProposalTransitionLock).not.toHaveBeenCalled();
  });
});
