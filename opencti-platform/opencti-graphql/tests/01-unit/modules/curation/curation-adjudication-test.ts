import { describe, expect, it } from 'vitest';
import {
  ADJUDICATED_PROPOSAL_KINDS,
  adjudicationDecisionsFor,
  buildAdjudicationContent,
  isProposalAdjudicable,
  parseAdjudicationResponse,
} from '../../../../src/modules/curation/curation-adjudication';
import { PROPOSAL_KINDS } from '../../../../src/modules/curation/curation-types';

describe('curation adjudication scope', () => {
  it('adjudicates the duplicate proposals of the ambiguous band', () => {
    expect(isProposalAdjudicable({ proposal_kind: 'merge', in_ambiguous_band: true })).toBe(true);
    expect(isProposalAdjudicable({ proposal_kind: 'alias', in_ambiguous_band: true })).toBe(true);
  });

  it('never adjudicates a confident proposal', () => {
    expect(isProposalAdjudicable({ proposal_kind: 'merge', in_ambiguous_band: false })).toBe(false);
  });

  it('leaves every other proposal kind to the analysts', () => {
    PROPOSAL_KINDS.filter((kind) => !ADJUDICATED_PROPOSAL_KINDS.includes(kind)).forEach((kind) => {
      expect(isProposalAdjudicable({ proposal_kind: kind, in_ambiguous_band: true })).toBe(false);
    });
  });
});

describe('curation adjudication answer', () => {
  const subjects = ['subject-a', 'subject-b'];

  it('reads one JSON object, fenced or not, with a target among the subjects', () => {
    const answer = '```json\n{"decision": "Merge", "rationale": "Same actor", "target_id": "subject-b"}\n```';
    expect(parseAdjudicationResponse(answer, subjects)).toEqual({ decision: 'merge', rationale: 'Same actor', target_id: 'subject-b' });
  });

  it('keeps a decision that names no target', () => {
    expect(parseAdjudicationResponse('{"decision": "distinct", "rationale": "Different victimology"}', subjects))
      .toEqual({ decision: 'distinct', rationale: 'Different victimology', target_id: null });
    expect(parseAdjudicationResponse('{"decision": "skip", "rationale": "Not enough evidence", "target_id": null}', subjects))
      .toEqual({ decision: 'skip', rationale: 'Not enough evidence', target_id: null });
  });

  it('refuses an answer naming a target outside the proposal, whatever agent wrote it', () => {
    expect(parseAdjudicationResponse('{"decision": "merge", "rationale": "Same actor", "target_id": "another-entity"}', subjects)).toBeNull();
    expect(parseAdjudicationResponse('{"decision": "alias", "rationale": "Same actor", "target_id": 42}', subjects)).toBeNull();
  });

  it('refuses an unknown decision, an empty rationale or an answer without JSON', () => {
    expect(parseAdjudicationResponse('{"decision": "delete", "rationale": "No"}', subjects)).toBeNull();
    expect(parseAdjudicationResponse('{"decision": "merge", "rationale": "  "}', subjects)).toBeNull();
    expect(parseAdjudicationResponse('They are the same actor.', subjects)).toBeNull();
    expect(parseAdjudicationResponse(null, subjects)).toBeNull();
  });

  it('refuses a merge of a single subject, and takes the other decisions on it', () => {
    expect(parseAdjudicationResponse('{"decision": "merge", "rationale": "Same actor"}', ['subject-a'])).toBeNull();
    expect(parseAdjudicationResponse('{"decision": "alias", "rationale": "MITRE lists the names", "target_id": "subject-a"}', ['subject-a']))
      .toEqual({ decision: 'alias', rationale: 'MITRE lists the names', target_id: 'subject-a' });
    expect(parseAdjudicationResponse('{"decision": "distinct", "rationale": "The names belong to another actor"}', ['subject-a']))
      .toEqual({ decision: 'distinct', rationale: 'The names belong to another actor', target_id: null });
  });
});

describe('curation adjudication request', () => {
  const subject = { internal_id: 'subject-a', entity_type: 'Intrusion-Set', name: 'Sandworm Team', aliasesIntrusionSet: [] } as never;
  const documentOf = (content: string) => JSON.parse(content.slice(content.indexOf('{')));

  it('sends the names an alias proposal adds, and no merge decision for a single subject', () => {
    const proposal = {
      internal_id: 'proposal-a',
      proposal_kind: 'alias',
      recommended_action: 'add_aliases',
      subject_ids: ['subject-a'],
      target_id: 'subject-a',
      action_payload: JSON.stringify({ aliases: ['ELECTRUM', 'Telebots'], cluster: 'G0034' }),
    } as never;
    const document = documentOf(buildAdjudicationContent(proposal, [subject]));
    expect(document.proposed_aliases).toEqual(['ELECTRUM', 'Telebots']);
    // The Curator reads the explanation the analysts read.
    expect(document.explanation).toMatch(/^Add 2 aliases to /);
    expect(document.explanation).toContain('Why: ');
    expect(document.allowed_decisions).toEqual(adjudicationDecisionsFor(['subject-a']));
    expect(document.allowed_decisions).not.toContain('merge');
  });

  it('offers every decision on a duplicate pair, without proposed names', () => {
    const proposal = { internal_id: 'proposal-b', proposal_kind: 'merge', subject_ids: ['subject-a', 'subject-b'], target_id: null } as never;
    const document = documentOf(buildAdjudicationContent(proposal, [subject]));
    expect(document.proposed_aliases).toBeUndefined();
    expect(document.allowed_decisions).toEqual(['alias', 'merge', 'distinct', 'skip']);
  });
});
