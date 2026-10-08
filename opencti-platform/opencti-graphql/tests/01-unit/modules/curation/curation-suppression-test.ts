import { describe, expect, it } from 'vitest';
import { isSuppressingDecision, payloadElementIds, proposalsOfMissingSubjects } from '../../../../src/modules/curation/curation-proposals';
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

  it('retires the proposals whose action names a deleted relationship, its subjects all there', () => {
    const relationships = (...ids: string[]) => JSON.stringify({ relationships: ids.map((id, index) => ({ actor_id: `actor-${index}`, relationship_id: id })) });
    const open = [
      { internal_id: 'both-attributions', subject_ids: ['campaign', 'actor-0', 'actor-1'], action_payload: relationships('rel-0', 'rel-1') },
      { internal_id: 'one-attribution-deleted', subject_ids: ['campaign', 'actor-0', 'actor-1'], action_payload: relationships('rel-0', 'rel-gone') },
    ];
    expect(proposalsOfMissingSubjects(open, new Set(['campaign', 'actor-0', 'actor-1', 'rel-0', 'rel-1'])).map((proposal) => proposal.internal_id))
      .toEqual(['one-attribution-deleted']);
  });
});

describe('elements named by the action of a proposal', () => {
  it('names the relationships it acts on and the merge record a split reverts, whose sources it shows', () => {
    expect(payloadElementIds(JSON.stringify({ relationships: [{ actor_id: 'actor', relationship_id: 'rel-0' }] }))).toEqual(['rel-0']);
    expect(payloadElementIds({ relationship_id: 'rel-1', previous: {}, current: {} })).toEqual(['rel-1']);
    expect(payloadElementIds({ merge_record_id: 'record-id' })).toEqual(['record-id']);
    expect(payloadElementIds('{not json')).toEqual([]);
  });
});
