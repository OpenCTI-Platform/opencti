import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { bulkAcceptProposals } from '../../../../src/modules/curation/curation-domain';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { createListTask } from '../../../../src/domain/backgroundTask-common';
import { ACTION_ACKNOWLEDGE, ACTION_MERGE } from '../../../../src/modules/curation/curation-types';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));

vi.mock('../../../../src/domain/backgroundTask-common', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/domain/backgroundTask-common')>()),
  createListTask: vi.fn(async () => ({ id: 'task-id' })),
}));

const userWith = (capabilities: string[]) => ({ id: 'user-id', capabilities: capabilities.map((name) => ({ name })) }) as unknown as AuthUser;
const proposal = (id: string, action: string, updatedAt = '2026-10-06T16:00:00.000Z') => ({
  internal_id: id,
  standard_id: id,
  recommended_action: action,
  proposal_kind: 'merge',
  updated_at: updatedAt,
});

describe('curation bulk accept', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('refuses the proposals the user could not apply one by one, instead of queuing them for a worker', async () => {
    (internalFindByIds as any).mockResolvedValue([proposal('merge-1', ACTION_MERGE), proposal('stale-1', ACTION_ACKNOWLEDGE)]);
    const editor = userWith(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE']);
    await expect(bulkAcceptProposals({} as AuthContext, editor, ['merge-1', 'stale-1'])).rejects.toThrow('You are not allowed to apply some of the selected curation proposals');
    expect(createListTask).not.toHaveBeenCalled();
    const merger = userWith(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNMERGE']);
    await expect(bulkAcceptProposals({} as AuthContext, merger, ['merge-1', 'stale-1'])).resolves.toBe('task-id');
    expect(createListTask).toHaveBeenCalledTimes(1);
  });

  it('refuses up front a proposal whose subject the user can no longer read, before its restrictions are refreshed', async () => {
    vi.mocked(internalFindByIds)
      .mockResolvedValueOnce([{ ...proposal('merge-1', ACTION_MERGE), subject_ids: ['reclassified-id'] }] as never)
      .mockResolvedValueOnce([] as never)
      .mockResolvedValueOnce([{ internal_id: 'reclassified-id' }] as never);
    const merger = userWith(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNMERGE']);
    await expect(bulkAcceptProposals({} as AuthContext, merger, ['merge-1'])).rejects.toThrow('do not exist or are not accessible');
    expect(createListTask).not.toHaveBeenCalled();
  });

  it('queues each proposal with the revision it was accepted on, for the worker to send back', async () => {
    (internalFindByIds as any).mockResolvedValue([
      proposal('merge-1', ACTION_MERGE, '2026-10-06T16:00:01.000Z'),
      proposal('stale-1', ACTION_ACKNOWLEDGE, '2026-10-06T16:00:02.000Z'),
    ]);
    const merger = userWith(['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNUPDATE_KNMERGE']);
    await bulkAcceptProposals({} as AuthContext, merger, ['merge-1', 'stale-1']);
    expect(vi.mocked(createListTask).mock.calls[0][2]).toEqual(expect.objectContaining({
      actions: [{
        type: 'CURATION_APPLY',
        context: { values: [], revisions: { 'merge-1': '2026-10-06T16:00:01.000Z', 'stale-1': '2026-10-06T16:00:02.000Z' } },
      }],
    }));
  });
});
