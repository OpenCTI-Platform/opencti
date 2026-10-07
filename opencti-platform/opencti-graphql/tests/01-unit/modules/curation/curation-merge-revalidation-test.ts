import { beforeEach, describe, expect, it, vi } from 'vitest';
import { acceptProposal, decideProposal } from '../../../../src/modules/curation/curation-domain';
import { internalFindByIds, storeLoadById } from '../../../../src/database/middleware-loader';
import { executeProposalAction } from '../../../../src/modules/curation/curation-apply';
import { currentMergeConfidence } from '../../../../src/modules/curation/curation-scan';
import { patchAttribute } from '../../../../src/database/middleware';
import { redisCurationSetApplicationResult } from '../../../../src/database/redis';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
  internalFindByIds: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  patchAttribute: vi.fn(async () => ({ element: { internal_id: 'proposal-id', proposal_status: 'accepted' } })),
}));
vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisCurationGetApplicationResult: vi.fn(async () => null),
  redisCurationSetApplicationResult: vi.fn(async () => undefined),
  redisCurationDeleteApplicationResult: vi.fn(async () => undefined),
}));
vi.mock('../../../../src/listener/UserActionListener', () => ({ publishUserAction: vi.fn(async () => undefined) }));
vi.mock('../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/manager/telemetryManager')>()),
  addCurationProposalAcceptedCount: vi.fn(),
}));
vi.mock('../../../../src/modules/curation/curation-apply', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-apply')>()),
  executeProposalAction: vi.fn(async () => ({ appliedPatch: null, mergeRecordId: 'record-id' })),
  findLatestMergeRecordForProposal: vi.fn(async () => null),
  hasInterruptedMergeForProposal: vi.fn(async () => false),
}));
vi.mock('../../../../src/modules/curation/curation-scan', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-scan')>()),
  currentMergeConfidence: vi.fn(),
}));
vi.mock('../../../../src/modules/curation/curation-settings', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-settings')>()),
  getCurationSettings: vi.fn(async () => ({})),
}));
vi.mock('../../../../src/modules/curation/curation-locks', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-locks')>()),
  withProposalTransitionLock: vi.fn(async (_id: string, callback: () => Promise<unknown>) => callback()),
}));
vi.mock('../../../../src/modules/curation/curation-readability', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-readability')>()),
  keepWithReadableParticipants: vi.fn(async (_context: unknown, _user: unknown, elements: unknown[]) => elements),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
const RAISED_AT = '2026-10-07T01:00:00.000Z';
const BEFORE = '2026-10-07T00:30:00.000Z';
const AFTER = '2026-10-07T01:30:00.000Z';

const mergeProposal = (overrides: Record<string, unknown> = {}) => ({
  internal_id: 'proposal-id',
  name: 'Merge Fancy Bear into APT28',
  proposal_kind: 'merge',
  proposal_status: 'open',
  recommended_action: 'merge',
  subject_ids: ['first-id', 'second-id'],
  subject_types: ['Intrusion-Set', 'Intrusion-Set'],
  target_id: 'first-id',
  created_at: RAISED_AT,
  updated_at: RAISED_AT,
  ...overrides,
});

const subjectsUpdated = (secondUpdatedAt: string) => [
  { internal_id: 'first-id', updated_at: BEFORE },
  { internal_id: 'second-id', updated_at: secondUpdatedAt },
];

describe('curation merge of a finding whose subjects changed', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('refuses the merge when a subject changed since the proposal was raised and the detectors no longer find the pair', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal() as never);
    vi.mocked(internalFindByIds).mockResolvedValue(subjectsUpdated(AFTER) as never);
    vi.mocked(currentMergeConfidence).mockResolvedValue(null);
    await expect(acceptProposal(context, user, 'proposal-id')).rejects.toThrow('the detectors no longer find them duplicates');
    expect(currentMergeConfidence).toHaveBeenCalledWith(context, {}, { subject_ids: ['first-id', 'second-id'] });
    expect(executeProposalAction).not.toHaveBeenCalled();
  });

  it('merges the subjects that changed when the detectors still find them duplicates', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal() as never);
    vi.mocked(internalFindByIds).mockResolvedValue(subjectsUpdated(AFTER) as never);
    vi.mocked(currentMergeConfidence).mockResolvedValue(0.82);
    await acceptProposal(context, user, 'proposal-id');
    expect(executeProposalAction).toHaveBeenCalledTimes(1);
  });

  it('does not run the detectors again when no subject changed since the proposal was raised', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal() as never);
    vi.mocked(internalFindByIds).mockResolvedValue(subjectsUpdated(BEFORE) as never);
    await acceptProposal(context, user, 'proposal-id');
    expect(currentMergeConfidence).not.toHaveBeenCalled();
    expect(executeProposalAction).toHaveBeenCalledTimes(1);
  });

  it('checks only the subjects that remain, and leaves a merge with one subject left to the merge itself', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal({ subject_ids: ['first-id', 'second-id', 'third-id'], subject_types: ['Intrusion-Set', 'Intrusion-Set', 'Intrusion-Set'] }) as never);
    vi.mocked(internalFindByIds).mockResolvedValueOnce(subjectsUpdated(AFTER) as never);
    vi.mocked(currentMergeConfidence).mockResolvedValue(0.9);
    await acceptProposal(context, user, 'proposal-id');
    expect(currentMergeConfidence).toHaveBeenCalledWith(context, {}, { subject_ids: ['first-id', 'second-id'] });

    vi.mocked(currentMergeConfidence).mockClear();
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ internal_id: 'first-id', updated_at: AFTER }] as never);
    await acceptProposal(context, user, 'proposal-id');
    expect(currentMergeConfidence).not.toHaveBeenCalled();
  });

  it('applies the same check to a merge decision applied through the API, not to an alias decision', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal() as never);
    vi.mocked(internalFindByIds).mockResolvedValue(subjectsUpdated(AFTER) as never);
    vi.mocked(currentMergeConfidence).mockResolvedValue(null);
    await expect(decideProposal(context, user, 'proposal-id', { decision: 'merge', rationale: 'Same actor', apply: true }))
      .rejects.toThrow('the detectors no longer find them duplicates');
    await decideProposal(context, user, 'proposal-id', { decision: 'alias', rationale: 'A sub-group', apply: true, target_id: 'first-id' });
    expect(currentMergeConfidence).toHaveBeenCalledTimes(1);
    expect(executeProposalAction).toHaveBeenCalledTimes(1);
  });

  it('completes a merge whose application already started without checking it again', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal({ application_started_at: AFTER }) as never);
    vi.mocked(internalFindByIds).mockResolvedValue(subjectsUpdated(AFTER) as never);
    await acceptProposal(context, user, 'proposal-id');
    expect(currentMergeConfidence).not.toHaveBeenCalled();
    expect(executeProposalAction).toHaveBeenCalledTimes(1);
  });
});

describe('curation start of a proposal application', () => {
  const startWrites = () => vi.mocked(patchAttribute).mock.calls.filter(([, , , , patch]) => 'application_started_at' in (patch as Record<string, unknown>));
  const planThenApply = async (...args: Parameters<typeof executeProposalAction>) => {
    await args[4]?.onBeforeChange?.({ appliedPatch: null, mergeRecordId: null });
    return { appliedPatch: null, mergeRecordId: 'record-id' };
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(internalFindByIds).mockResolvedValue(subjectsUpdated(BEFORE) as never);
  });

  it('leaves a proposal whose action refused to apply as it was read, not marked as being applied', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal() as never);
    vi.mocked(executeProposalAction).mockRejectedValueOnce(new Error('Nothing left to merge'));
    await expect(acceptProposal(context, user, 'proposal-id')).rejects.toThrow('Nothing left to merge');
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(redisCurationSetApplicationResult).not.toHaveBeenCalled();
  });

  it('marks the start once the action is about to change the graph, after its planned change is kept', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal() as never);
    vi.mocked(executeProposalAction).mockImplementationOnce(planThenApply);
    await acceptProposal(context, user, 'proposal-id');
    expect(startWrites()).toHaveLength(1);
    const startCall = vi.mocked(patchAttribute).mock.calls.indexOf(startWrites()[0]);
    expect(vi.mocked(redisCurationSetApplicationResult).mock.invocationCallOrder[0])
      .toBeLessThan(vi.mocked(patchAttribute).mock.invocationCallOrder[startCall]);
  });

  it('does not mark again the start of an application run again', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(mergeProposal({ application_started_at: AFTER }) as never);
    vi.mocked(executeProposalAction).mockImplementationOnce(planThenApply);
    await acceptProposal(context, user, 'proposal-id');
    expect(redisCurationSetApplicationResult).toHaveBeenCalledTimes(1);
    expect(startWrites()).toHaveLength(0);
  });
});
