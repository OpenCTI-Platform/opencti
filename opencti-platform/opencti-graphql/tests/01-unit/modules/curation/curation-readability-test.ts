import { beforeEach, describe, expect, it, vi } from 'vitest';
import { keepWithReadableParticipants } from '../../../../src/modules/curation/curation-readability';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { getEntityFromCache } from '../../../../src/database/cache';
import { SYSTEM_USER } from '../../../../src/utils/access';
import type { BasicStoreBase } from '../../../../src/types/store';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntityFromCache: vi.fn(),
}));

const context = { user_inside_platform_organization: false } as unknown as AuthContext;
const analyst = {
  id: 'analyst-id',
  capabilities: [{ name: 'KNOWLEDGE' }],
  organizations: [{ internal_id: 'org-a', standard_id: 'identity--org-a' }],
} as unknown as AuthUser;

const target = { internal_id: 'target', standard_id: 'intrusion-set--target', entity_type: 'Intrusion-Set', granted: ['org-a', 'org-b'] };
const recordOf = (id: string, organizations: string[]) => ({ internal_id: id, standard_id: `merge-record--${id}`, entity_type: 'MergeRecord', granted: organizations });
const sharedRecord = recordOf('record-shared', ['org-a']);
const otherRecord = recordOf('record-other', ['org-b']);
const stored = [target, sharedRecord, otherRecord] as unknown as BasicStoreBase[];

type Split = BasicStoreBase & { record_id: string };
const splitOf = (id: string, recordId: string) => ({ internal_id: id, record_id: recordId }) as unknown as Split;
const splits = [splitOf('split-shared', 'record-shared'), splitOf('split-other', 'record-other')];
const participantsOf = (split: Split) => ['target', split.record_id];

describe('the participants of a curation record', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // The store segregates internal objects by markings only: every merge record is found for the analyst.
    vi.mocked(internalFindByIds).mockImplementation(async (_context, _user, ids) => stored.filter((element) => ids.includes(element.internal_id)) as never);
  });

  it('reads a merge record by the organizations it is shared with when the platform has an organization', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: 'platform-org' } as never);
    const kept = await keepWithReadableParticipants(context, analyst, splits, participantsOf);
    expect(kept.map((split) => split.internal_id)).toEqual(['split-shared']);
    // The hidden record exists: the split proposal that names its sources is hidden, not left to its own restrictions.
    expect(vi.mocked(internalFindByIds).mock.calls[1][1]).toBe(SYSTEM_USER);
  });

  it('keeps organization sharing out of the check without a platform organization, as the platform does', async () => {
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_organization: null } as never);
    const kept = await keepWithReadableParticipants(context, analyst, splits, participantsOf);
    expect(kept.map((split) => split.internal_id)).toEqual(['split-shared', 'split-other']);
  });

  it('does not read the settings when no participant is a merge record', async () => {
    const kept = await keepWithReadableParticipants(context, analyst, [splitOf('merge', 'target')], (split) => [split.record_id]);
    expect(kept).toHaveLength(1);
    expect(getEntityFromCache).not.toHaveBeenCalled();
  });
});
