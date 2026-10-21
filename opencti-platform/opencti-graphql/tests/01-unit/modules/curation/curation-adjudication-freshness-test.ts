import { describe, expect, it } from 'vitest';
import { adjudicationDecidesAction } from '../../../../src/modules/curation/curation-access';
import { adjudicatedContent, refreshedContentChanges } from '../../../../src/modules/curation/curation-proposals';
import { ACTION_ADD_ALIASES, ACTION_FIX_DATES, ACTION_MERGE, type BasicStoreEntityCurationProposal } from '../../../../src/modules/curation/curation-types';

const proposal = (overrides: Partial<BasicStoreEntityCurationProposal> = {}) => ({
  subject_ids: ['cl0p', 'clop'],
  subject_names: ['Cl0p', 'Clop'],
  confidence_score: 0.71,
  curation_evidence: [{ evidence_type: 'trigram', score: 0.86, weight: 0.25, description: 'Names differ by one character.' }],
  action_payload: null,
  ...overrides,
} as unknown as BasicStoreEntityCurationProposal);

describe('what an adjudication judges', () => {
  it('is the same case while the subjects, the names, the finding and the proposed change are', () => {
    expect(adjudicatedContent(proposal())).toBe(adjudicatedContent(proposal()));
    // Restrictions, the request time or the adjudication itself are not what it judged.
    expect(adjudicatedContent(proposal({ adjudication_requested_at: '2026-10-05T05:00:00.000Z' }))).toBe(adjudicatedContent(proposal()));
  });

  it('is another case once the proposal was refreshed with other content', () => {
    const base = adjudicatedContent(proposal());
    expect(adjudicatedContent(proposal({ subject_names: ['Cl0p', 'Clop Group'] }))).not.toBe(base);
    expect(adjudicatedContent(proposal({ confidence_score: 0.82 }))).not.toBe(base);
    expect(adjudicatedContent(proposal({ curation_evidence: [] }))).not.toBe(base);
    expect(adjudicatedContent(proposal({ action_payload: JSON.stringify({ aliases: ['TA505'] }) }))).not.toBe(base);
  });
});

describe('what a new detection of an open finding changes', () => {
  const evidence = [{ evidence_type: 'trigram', score: 0.86, weight: 0.25, description: 'Names differ by one character.' }];
  const stored = proposal({ target_id: 'cl0p', recommended_action: ACTION_MERGE, action_payload: { survivor: 'cl0p', sources: ['clop'] } as never });
  type Draft = Parameters<typeof refreshedContentChanges>[1];
  const draft: Draft = { confidence: 0.71, evidence, target_id: 'cl0p', recommended_action: ACTION_MERGE, action_payload: { sources: ['clop'], survivor: 'cl0p', note: undefined } };

  it('changes nothing for the same finding and recommendation, whatever the order or the form of the stored payload', () => {
    expect(refreshedContentChanges(stored, draft)).toEqual({ finding: false, executable: false });
    const legacy = proposal({ target_id: 'cl0p', recommended_action: ACTION_MERGE, action_payload: JSON.stringify({ survivor: 'cl0p', sources: ['clop'] }) });
    expect(refreshedContentChanges(legacy, draft).executable).toBe(false);
    expect(refreshedContentChanges(proposal({ recommended_action: ACTION_MERGE }), { ...draft, target_id: undefined, action_payload: undefined }).executable).toBe(false);
  });

  it('changes what accepting it executes when the survivor, the action or the payload differ', () => {
    expect(refreshedContentChanges(stored, { ...draft, target_id: 'clop' })).toEqual({ finding: false, executable: true });
    expect(refreshedContentChanges(stored, { ...draft, recommended_action: ACTION_ADD_ALIASES }).executable).toBe(true);
    expect(refreshedContentChanges(stored, { ...draft, action_payload: { survivor: 'clop', sources: ['cl0p'] } }).executable).toBe(true);
    expect(refreshedContentChanges(stored, { ...draft, confidence: 0.82 })).toEqual({ finding: true, executable: false });
  });
});

describe('an adjudication applied by an accepted proposal', () => {
  it('is applied only by the action it decided', () => {
    expect(adjudicationDecidesAction('merge', ACTION_MERGE)).toBe(true);
    expect(adjudicationDecidesAction('alias', ACTION_ADD_ALIASES)).toBe(true);
    // Accepting a merge after a distinct, skip or alias answer leaves that answer advisory.
    expect(adjudicationDecidesAction('distinct', ACTION_MERGE)).toBe(false);
    expect(adjudicationDecidesAction('skip', ACTION_MERGE)).toBe(false);
    expect(adjudicationDecidesAction('alias', ACTION_MERGE)).toBe(false);
    expect(adjudicationDecidesAction('merge', ACTION_FIX_DATES)).toBe(false);
    expect(adjudicationDecidesAction(null, ACTION_MERGE)).toBe(false);
  });
});
