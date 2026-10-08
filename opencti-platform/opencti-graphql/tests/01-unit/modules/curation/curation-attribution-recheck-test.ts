import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { executeProposalAction } from '../../../../src/modules/curation/curation-apply';
import { deleteElementById } from '../../../../src/database/middleware';
import { internalFindByIds } from '../../../../src/database/middleware-loader';
import { lockResources } from '../../../../src/lock/master-lock';
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
vi.mock('../../../../src/lock/master-lock', () => ({ lockResources: vi.fn(async () => ({ unlock: vi.fn(), signal: { throwIfAborted: vi.fn() } })) }));

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

  it('holds the lock of the attribution to keep from the check to the last deletion, and only that one', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([relation('rel-keep')] as never).mockResolvedValue([relation('rel-keep'), relation('rel-other')] as never);
    await executeProposalAction(context, user, conflict(), settings, KEEP);
    const lockedIds = vi.mocked(lockResources).mock.calls[0][0];
    expect(lockedIds).toEqual(expect.arrayContaining(['rel-keep', 'relationship--rel-keep']));
    expect(lockedIds).not.toContain('rel-other');
    const lock = await vi.mocked(lockResources).mock.results[0].value;
    const lockedAt = vi.mocked(lockResources).mock.invocationCallOrder[0];
    // The attributions in conflict are read again under the lock, and deleted before it is released.
    expect(vi.mocked(internalFindByIds).mock.invocationCallOrder.slice(1).every((order) => order > lockedAt)).toBe(true);
    expect(vi.mocked(deleteElementById).mock.invocationCallOrder[0]).toBeLessThan(lock.unlock.mock.invocationCallOrder[0]);
  });

  it('refuses when the attribution to keep was deleted, so the last one left is never removed', async () => {
    vi.mocked(internalFindByIds).mockResolvedValueOnce([] as never);
    remainingAttributions('rel-other');
    await expect(executeProposalAction(context, user, conflict(), settings, KEEP)).rejects.toThrow('The attribution to keep was deleted');
    expect(deleteElementById).not.toHaveBeenCalled();
    // A recently deleted element cannot be locked: nothing is locked when no attribution to keep is left.
    expect(lockResources).not.toHaveBeenCalled();
  });

  it('releases the lock of the attribution to keep when it refuses', async () => {
    remainingAttributions('rel-keep');
    await expect(executeProposalAction(context, user, conflict(), settings, KEEP)).rejects.toThrow('so the contradiction is resolved');
    expect((await vi.mocked(lockResources).mock.results[0].value).unlock).toHaveBeenCalled();
  });

  it('refuses when only the attribution to keep remains: the contradiction is resolved', async () => {
    remainingAttributions('rel-keep');
    await expect(executeProposalAction(context, user, conflict(), settings, KEEP)).rejects.toThrow('so the contradiction is resolved');
    expect(deleteElementById).not.toHaveBeenCalled();
  });

  it('refuses again after an attempt that was refused, whose acceptance had started', async () => {
    remainingAttributions('rel-keep');
    const again = conflict({ application_started_at: '2026-10-07T03:00:00.000Z' });
    await expect(executeProposalAction(context, user, again, settings, KEEP)).rejects.toThrow('so the contradiction is resolved');
    expect(deleteElementById).not.toHaveBeenCalled();
  });
});
