import { beforeEach, describe, expect, it, vi } from 'vitest';
import { persistProposalDraft } from '../../../../src/modules/curation/curation-proposals';
import { fullEntitiesList, internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { patchAttribute, updateAttribute } from '../../../../src/database/middleware';
import { withProposalTransitionLock } from '../../../../src/modules/curation/curation-locks';
import { TYPE_LOCK_ERROR } from '../../../../src/config/errors';
import { INPUT_MARKINGS } from '../../../../src/schema/general';
import { RELATION_OBJECT_MARKING } from '../../../../src/schema/stixRefRelationship';
import { ACTION_MERGE, DETECTOR_SIMILARITY, PROPOSAL_KIND_MERGE } from '../../../../src/modules/curation/curation-types';
import type { CurationSettings, ProposalDraft } from '../../../../src/modules/curation/curation-types';
import type { AuthContext } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  fullEntitiesList: vi.fn(),
  internalFindByIds: vi.fn(),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  patchAttribute: vi.fn(async (_context: unknown, _user: unknown, id: string, _type: string, patch: Record<string, unknown>) => ({ element: { internal_id: id, ...patch } })),
  updateAttribute: vi.fn(async (_context: unknown, _user: unknown, id: string) => ({ element: { internal_id: id } })),
}));
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntityFromCache: vi.fn(async () => ({})),
}));
vi.mock('../../../../src/modules/curation/curation-locks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-locks')>()),
  withProposalFingerprintLock: vi.fn(async (_fingerprint: string, callback: () => Promise<unknown>) => callback()),
  withProposalTransitionLock: vi.fn(async (_id: string, callback: () => Promise<unknown>) => callback()),
}));

const context = {} as AuthContext;
const settings = { ambiguous_band_min: 0.5, ambiguous_band_max: 0.6 } as CurationSettings;

const draft: ProposalDraft = {
  kind: PROPOSAL_KIND_MERGE,
  detector: DETECTOR_SIMILARITY,
  subjects: [
    { id: 'first-id', entity_type: 'Intrusion-Set', name: 'APT28' },
    { id: 'second-id', entity_type: 'Intrusion-Set', name: 'Fancy Bear' },
  ],
  target_id: 'first-id',
  recommended_action: ACTION_MERGE,
  action_payload: null,
  evidence: [],
  confidence: 0.9,
};

const proposal = (overrides: Record<string, unknown> = {}) => ({
  internal_id: 'proposal-id',
  proposal_kind: PROPOSAL_KIND_MERGE,
  proposal_status: 'open',
  subject_ids: ['first-id', 'second-id'],
  subject_names: ['APT28', 'Fancy Bear'],
  target_id: 'first-id',
  recommended_action: ACTION_MERGE,
  action_payload: null,
  curation_evidence: [],
  confidence_score: 0.7,
  in_ambiguous_band: false,
  ...overrides,
});

describe('curation refresh of a proposal found again', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(fullEntitiesList).mockResolvedValue([proposal()] as never);
    vi.mocked(internalFindByIds).mockResolvedValue([
      { internal_id: 'first-id', name: 'APT28' },
      { internal_id: 'second-id', name: 'Fancy Bear' },
    ] as never);
  });

  it('refreshes the proposal read again under its transition lock, without waiting for that lock', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(proposal() as never);
    const result = await persistProposalDraft(context, settings, draft);
    expect(withProposalTransitionLock).toHaveBeenCalledWith('proposal-id', expect.any(Function), { retryCount: 0 });
    expect(updateAttribute).toHaveBeenCalledWith(context, expect.anything(), 'proposal-id', expect.any(String), expect.arrayContaining([
      expect.objectContaining({ key: 'confidence_score', value: [0.9] }),
    ]));
    expect(result).toMatchObject({ proposal: { internal_id: 'proposal-id' }, created: false, suppressed: false });
  });

  it('writes widened restrictions in the same update as the content they protect', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(proposal({ [RELATION_OBJECT_MARKING]: ['marking-red'] }) as never);
    await persistProposalDraft(context, settings, draft);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
    expect(updateAttribute).toHaveBeenCalledWith(context, expect.anything(), 'proposal-id', expect.any(String), expect.arrayContaining([
      expect.objectContaining({ key: INPUT_MARKINGS, value: [] }),
      expect.objectContaining({ key: 'confidence_score', value: [0.9] }),
    ]));
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('leaves a proposal decided since it was found as the decision left it', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(proposal({ proposal_status: 'accepted' }) as never);
    const result = await persistProposalDraft(context, settings, draft);
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(result).toMatchObject({ created: false, suppressed: false });
  });

  it('leaves a proposal whose application started since it was found with the content that application read', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(proposal({ application_started_at: '2026-10-07T07:00:00.000Z' }) as never);
    await persistProposalDraft(context, settings, draft);
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('leaves a proposal a decision holds as it is, so the next detection refreshes it if it stays open', async () => {
    vi.mocked(withProposalTransitionLock).mockRejectedValueOnce(Object.assign(new Error('Lock held'), { name: TYPE_LOCK_ERROR }));
    const result = await persistProposalDraft(context, settings, draft);
    expect(storeLoadById).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(result).toMatchObject({ proposal: { internal_id: 'proposal-id' }, created: false, suppressed: false });
  });

  it('lets any other failure of the refresh through', async () => {
    vi.mocked(withProposalTransitionLock).mockRejectedValueOnce(new Error('Search engine unavailable'));
    await expect(persistProposalDraft(context, settings, draft)).rejects.toThrow('Search engine unavailable');
  });
});
