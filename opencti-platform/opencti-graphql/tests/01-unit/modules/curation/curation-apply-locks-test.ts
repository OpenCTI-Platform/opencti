import { beforeEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { executeProposalAction, procedureNoteStixId } from '../../../../src/modules/curation/curation-apply';
import { createEntity, storeLoadByIdWithRefs, updateAttribute } from '../../../../src/database/middleware';
import { fullRelationsList, internalFindByIds, pageRelationsConnection } from '../../../../src/database/middleware-loader';
import { lockResources } from '../../../../src/lock/master-lock';
import { EVIDENCE_STALENESS, type BasicStoreEntityCurationProposal, type CurationSettings } from '../../../../src/modules/curation/curation-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  storeLoadByIdWithRefs: vi.fn(),
  updateAttribute: vi.fn(async () => ({ element: {} })),
  createEntity: vi.fn(async () => ({ internal_id: 'note-id' })),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  pageRelationsConnection: vi.fn(),
  fullRelationsList: vi.fn(async () => []),
  internalFindByIds: vi.fn(async () => []),
}));
vi.mock('../../../../src/lock/master-lock', () => ({ lockResources: vi.fn(async () => ({ unlock: vi.fn(), signal: { throwIfAborted: vi.fn() } })) }));
vi.mock('../../../../src/utils/confidence-level', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/utils/confidence-level')>()),
  controlUserConfidenceAgainstElement: vi.fn(),
}));

const context = {} as AuthContext;
const user = { id: 'analyst-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;
const settings = {} as CurationSettings;
const longAgo = '2020-01-01T00:00:00.000Z';

const proposal = (overrides: Partial<BasicStoreEntityCurationProposal>) => ({
  internal_id: 'proposal-id',
  subject_ids: ['subject-id'],
  target_id: 'subject-id',
  ...overrides,
} as unknown as BasicStoreEntityCurationProposal);

describe('curation actions under the entity lock', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('reads the aliases under the lock, so an alias added meanwhile is kept', async () => {
    const before = { internal_id: 'subject-id', standard_id: 'intrusion-set--subject', entity_type: 'Intrusion-Set', name: 'Cl0p', aliases: ['TA505'] };
    const underLock = { ...before, aliases: ['TA505', 'Graceful Spider'] };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(before as never).mockResolvedValueOnce(underLock as never);
    await executeProposalAction(context, user, proposal({ proposal_kind: 'alias', recommended_action: 'add_aliases', action_payload: { aliases: ['FIN11'] } as never }), settings);
    expect(vi.mocked(lockResources).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(storeLoadByIdWithRefs).mock.invocationCallOrder[1]);
    expect(updateAttribute).toHaveBeenCalledWith(context, user, 'subject-id', 'Intrusion-Set', [{ key: 'aliases', value: ['TA505', 'Graceful Spider', 'FIN11'] }], { locks: expect.any(Array) });
  });

  it('puts a revoked entity back when it gained a relationship during the revocation', async () => {
    const element = { internal_id: 'subject-id', standard_id: 'intrusion-set--subject', entity_type: 'Intrusion-Set', name: 'Cl0p', revoked: false, updated_at: longAgo };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue(element as never);
    vi.mocked(pageRelationsConnection).mockResolvedValueOnce({ edges: [] } as never).mockResolvedValueOnce({ edges: [{ node: {} }] } as never);
    const stale = proposal({
      proposal_kind: 'stale',
      recommended_action: 'revoke',
      curation_evidence: [{ evidence_type: EVIDENCE_STALENESS, details: JSON.stringify({ months: 24 }) }] as never,
    });
    await expect(executeProposalAction(context, user, stale, settings)).rejects.toThrow('not stale any more');
    // The check runs under the lock, then the revocation, then the entity is put back as it was.
    expect(vi.mocked(lockResources).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(pageRelationsConnection).mock.invocationCallOrder[0]);
    expect(vi.mocked(updateAttribute).mock.calls.map((call) => call[4])).toEqual([[{ key: 'revoked', value: [true] }], [{ key: 'revoked', value: [false] }]]);
    expect(vi.mocked(updateAttribute).mock.calls.every((call) => Array.isArray((call[5] as { locks?: string[] })?.locks))).toBe(true);
  });

  it('revokes a stale entity that stayed inactive', async () => {
    const element = { internal_id: 'subject-id', standard_id: 'intrusion-set--subject', entity_type: 'Intrusion-Set', name: 'Cl0p', revoked: false, updated_at: longAgo };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue(element as never);
    vi.mocked(pageRelationsConnection).mockResolvedValue({ edges: [] } as never);
    const stale = proposal({
      proposal_kind: 'stale',
      recommended_action: 'revoke',
      curation_evidence: [{ evidence_type: EVIDENCE_STALENESS, details: JSON.stringify({ months: 24 }) }] as never,
    });
    const result = await executeProposalAction(context, user, stale, settings);
    expect(result.appliedPatch?.operations).toEqual([expect.objectContaining({ key: 'revoked', previous: false, value: true })]);
    expect(vi.mocked(updateAttribute).mock.calls.map((call) => call[4])).toEqual([[{ key: 'revoked', value: [true] }]]);
  });

  const datesProposal = proposal({ proposal_kind: 'contradiction', recommended_action: 'fix_dates', action_payload: { start_field: 'start_time', stop_field: 'stop_time' } as never });
  const relationship = { internal_id: 'subject-id', standard_id: 'relationship--subject', entity_type: 'uses' };

  it('checks the dates again under the lock, so a fix made meanwhile is not swapped back', async () => {
    const inverted = { ...relationship, start_time: '2024-06-01T00:00:00.000Z', stop_time: '2024-01-01T00:00:00.000Z' };
    const fixedMeanwhile = { ...relationship, start_time: '2024-01-01T00:00:00.000Z', stop_time: '2024-06-01T00:00:00.000Z' };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(inverted as never).mockResolvedValueOnce(fixedMeanwhile as never);
    await expect(executeProposalAction(context, user, datesProposal, settings)).rejects.toThrow('not inverted anymore');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('swaps inverted dates with the values read under the lock', async () => {
    const inverted = { ...relationship, start_time: '2024-06-01T00:00:00.000Z', stop_time: '2024-01-01T00:00:00.000Z' };
    const editedMeanwhile = { ...inverted, start_time: '2024-07-01T00:00:00.000Z' };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(inverted as never).mockResolvedValueOnce(editedMeanwhile as never);
    await executeProposalAction(context, user, datesProposal, settings);
    expect(updateAttribute).toHaveBeenCalledWith(context, user, 'subject-id', 'uses', [
      { key: 'start_time', value: ['2024-01-01T00:00:00.000Z'] },
      { key: 'stop_time', value: ['2024-07-01T00:00:00.000Z'] },
    ], { locks: expect.any(Array) });
  });

  it('does not restore an authoritative value over a write made while waiting for the lock', async () => {
    const element = { internal_id: 'subject-id', standard_id: 'malware--subject', entity_type: 'Malware', name: 'Emotet', description: 'Overwritten' };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValueOnce(element as never).mockResolvedValueOnce({ ...element, description: 'Written meanwhile' } as never);
    const authority = proposal({
      proposal_kind: 'field_precedence',
      recommended_action: 'set_field',
      action_payload: { key: 'description', value: 'Authoritative', overwritten_value: 'Overwritten' } as never,
    });
    await expect(executeProposalAction(context, user, authority, settings)).rejects.toThrow('written again');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  const indicator = { internal_id: 'subject-id', standard_id: 'indicator--subject', entity_type: 'Indicator', name: 'evil.example', revoked: true, updated_at: '2024-01-01T00:00:00.000Z' };
  const unrevoke = proposal({ proposal_kind: 'contradiction', recommended_action: 'unrevoke_indicator', action_payload: { indicator_id: 'subject-id' } as never });

  it('refuses to reactivate an indicator once no observable it is based on is active any more', async () => {
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue(indicator as never);
    vi.mocked(fullRelationsList).mockResolvedValueOnce([{ toId: 'observable-id' }] as never);
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ internal_id: 'observable-id', updated_at: '2024-02-01T00:00:00.000Z', x_opencti_score: 20 }] as never);
    await expect(executeProposalAction(context, user, unrevoke, settings)).rejects.toThrow('contradiction is resolved');
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  const activeObservable = () => {
    vi.mocked(fullRelationsList).mockResolvedValueOnce([{ toId: 'observable-id' }] as never);
    vi.mocked(internalFindByIds).mockResolvedValueOnce([{ internal_id: 'observable-id', updated_at: '2024-02-01T00:00:00.000Z', x_opencti_score: 80 }] as never);
  };
  const decayRule = { decay_lifetime: 470, decay_pound: 0.35, decay_points: [60, 40], decay_revoke_score: 20 };
  const inputKeys = () => vi.mocked(updateAttribute).mock.calls[0][4].map((input: { key: string }) => input.key);

  it('reactivates an indicator without decay rule with the default score and validity, as an edit of the indicator does', async () => {
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue({ ...indicator, x_opencti_score: 0 } as never);
    activeObservable();
    const result = await executeProposalAction(context, user, unrevoke, settings);
    const inputs = vi.mocked(updateAttribute).mock.calls[0][4];
    expect(inputs).toEqual(expect.arrayContaining([{ key: 'revoked', value: [false] }, { key: 'x_opencti_score', value: [50] }]));
    expect(inputKeys()).toEqual(expect.arrayContaining(['valid_from', 'valid_until']));
    expect(vi.mocked(updateAttribute).mock.calls[0][5]).toEqual({ locks: expect.any(Array) });
    // Every written field is recorded with its previous value, so a revert restores the indicator as it was.
    expect(result.appliedPatch?.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'revoked', previous: true, value: false }),
      expect.objectContaining({ key: 'x_opencti_score', previous: 0, value: 50 }),
    ]));
    expect(result.appliedPatch?.operations.map((operation) => operation.key).sort()).toEqual([...inputKeys()].sort());
  });

  it('restarts the decay of a decay-managed indicator from its base score when it is reactivated', async () => {
    const decayed = { ...indicator, x_opencti_score: 20, decay_applied_rule: decayRule, decay_base_score: 80, decay_base_score_date: '2024-01-01T00:00:00.000Z', decay_history: [] };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue(decayed as never);
    activeObservable();
    const result = await executeProposalAction(context, user, unrevoke, settings);
    expect(vi.mocked(updateAttribute).mock.calls[0][4]).toEqual(expect.arrayContaining([{ key: 'revoked', value: [false] }, { key: 'x_opencti_score', value: [80] }]));
    expect(inputKeys()).toEqual(expect.arrayContaining(['decay_base_score_date', 'decay_history', 'valid_until']));
    expect(result.appliedPatch?.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'x_opencti_score', previous: 20, value: 80 }),
      expect.objectContaining({ key: 'decay_base_score_date', previous: '2024-01-01T00:00:00.000Z' }),
    ]));
  });

  it('reactivates an indicator under a decay exclusion for its own bounded lifetime', async () => {
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue({ ...indicator, decay_exclusion_applied_rule: { decay_exclusion_id: 'exclusion-id' } } as never);
    activeObservable();
    await executeProposalAction(context, user, unrevoke, settings);
    expect(vi.mocked(updateAttribute).mock.calls[0][4]).toEqual([{ key: 'revoked', value: [false] }, { key: 'valid_until', value: [expect.any(String)] }]);
  });

  it('revokes a decayed indicator with its revoke score, no detection and a validity ending now', async () => {
    const decayed = { ...indicator, revoked: false, x_opencti_score: 20, x_opencti_detection: true, valid_until: '2030-01-01T00:00:00.000Z', decay_applied_rule: decayRule, decay_base_score: 80, decay_history: [] };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue(decayed as never);
    const stale = proposal({
      proposal_kind: 'stale',
      recommended_action: 'revoke',
      curation_evidence: [{ evidence_type: 'decayed_indicator', details: '{}' }] as never,
    });
    const result = await executeProposalAction(context, user, stale, settings);
    expect(vi.mocked(updateAttribute).mock.calls[0][4]).toEqual(expect.arrayContaining([{ key: 'revoked', value: [true] }, { key: 'x_opencti_detection', value: [false] }]));
    expect(inputKeys()).toEqual(expect.arrayContaining(['valid_until', 'decay_history']));
    expect(result.appliedPatch?.operations).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'revoked', previous: false, value: true }),
      expect.objectContaining({ key: 'valid_until', previous: '2030-01-01T00:00:00.000Z' }),
    ]));
  });

  it('records for the revert only the note this application created', async () => {
    const conflicting = { ...relationship, from: { name: 'APT28' }, to: { name: 'Spearphishing' }, fromId: 'from-id', toId: 'to-id' };
    vi.mocked(storeLoadByIdWithRefs).mockResolvedValue(conflicting as never);
    const preserve = proposal({
      proposal_kind: 'relationship_conflict',
      recommended_action: 'preserve_procedure',
      action_payload: { relationship_id: 'subject-id', previous: { text: 'Sends a macro document' }, current: { text: 'Sends a link' } } as never,
    });
    const result = await executeProposalAction(context, user, preserve, settings);
    expect(vi.mocked(createEntity).mock.calls[0][2]).toEqual(expect.objectContaining({ stix_id: procedureNoteStixId('proposal-id') }));
    expect(result.appliedPatch?.created_ids).toEqual(['note-id']);
    expect(procedureNoteStixId('proposal-id')).not.toEqual(procedureNoteStixId('other-proposal-id'));
  });
});
