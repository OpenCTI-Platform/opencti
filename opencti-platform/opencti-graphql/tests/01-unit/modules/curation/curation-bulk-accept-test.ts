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
const proposal = (id: string, action: string) => ({ internal_id: id, standard_id: id, recommended_action: action, proposal_kind: 'merge' });

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
});
