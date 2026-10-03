import { describe, expect, it } from 'vitest';
import { ADJUDICATED_PROPOSAL_KINDS, isProposalAdjudicable } from '../../../../src/modules/curation/curation-adjudication';
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
