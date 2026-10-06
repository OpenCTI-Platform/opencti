import { describe, expect, it } from 'vitest';
import { isSuppressingDecision, proposalsOfMissingSubjects } from '../../../../src/modules/curation/curation-proposals';
import {
  ACTION_ACKNOWLEDGE,
  ACTION_ADD_ALIASES,
  ACTION_FIX_DATES,
  ACTION_MERGE,
  ACTION_REVOKE,
  PROPOSAL_STATUS_ACCEPTED,
  PROPOSAL_STATUS_AUTO_APPLIED,
  PROPOSAL_STATUS_OPEN,
  PROPOSAL_STATUS_REJECTED,
  PROPOSAL_STATUS_REVERTED,
} from '../../../../src/modules/curation/curation-types';

describe('Curation finding suppression', () => {
  it('keeps a rejected, reverted or acknowledged finding from being proposed again', () => {
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_REJECTED, recommended_action: ACTION_MERGE })).toBe(true);
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_REVERTED, recommended_action: ACTION_ADD_ALIASES })).toBe(true);
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_ACCEPTED, recommended_action: ACTION_ACKNOWLEDGE })).toBe(true);
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_AUTO_APPLIED, recommended_action: ACTION_ACKNOWLEDGE })).toBe(true);
  });

  it('lets a fixed finding that comes back be proposed again', () => {
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_ACCEPTED, recommended_action: ACTION_FIX_DATES })).toBe(false);
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_ACCEPTED, recommended_action: ACTION_ADD_ALIASES })).toBe(false);
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_AUTO_APPLIED, recommended_action: ACTION_REVOKE })).toBe(false);
    expect(isSuppressingDecision({ proposal_status: PROPOSAL_STATUS_OPEN, recommended_action: ACTION_MERGE })).toBe(false);
  });
});

describe('open proposals about deleted entities', () => {
  it('retires the proposals naming a missing subject, unless an acceptance started to apply them', () => {
    const open = [
      { internal_id: 'both-there', subject_ids: ['a', 'b'] },
      { internal_id: 'one-deleted', subject_ids: ['a', 'deleted'] },
      { internal_id: 'being-applied', subject_ids: ['deleted'], application_started_at: '2026-10-06T00:00:00.000Z' },
    ];
    expect(proposalsOfMissingSubjects(open, new Set(['a', 'b'])).map((proposal) => proposal.internal_id)).toEqual(['one-deleted']);
  });
});
