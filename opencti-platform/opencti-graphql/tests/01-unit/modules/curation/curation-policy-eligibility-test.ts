import { describe, expect, it } from 'vitest';
import {
  EXCLUSION_ADJUDICATION_DISAGREES,
  EXCLUSION_ADJUDICATION_MISSING,
  EXCLUSION_CROSS_MARKINGS,
  EXCLUSION_CROSS_ORGANIZATIONS,
  EXCLUSION_MANUAL_CHOICE,
  computeSourceClass,
  evaluatePolicyEligibility,
} from '../../../../src/modules/curation/curation-policies';
import type { CurationAdjudication } from '../../../../src/modules/curation/curation-types';

const policy = {
  policy_kinds: ['merge', 'stale'],
  policy_entity_types: [],
  auto_apply_threshold: 0.9,
  policy_source_class: 'any',
  forbid_open_contradiction: false,
  require_adjudication: true,
} as unknown as Parameters<typeof evaluatePolicyEligibility>[0];

const facts = { markingSets: [[]], organizationSets: [[]], sourceClass: 'connector' as const, subjectsFound: true };

const proposal = (kind: string, adjudication: Partial<CurationAdjudication> | null) => ({
  proposal_status: 'open',
  proposal_kind: kind,
  subject_types: ['Intrusion-Set', 'Intrusion-Set'],
  subject_ids: ['a', 'b'],
  confidence_score: 0.95,
  recommended_action: kind === 'merge' ? 'merge' : 'revoke',
  curation_adjudication: adjudication
    ? { decision: 'merge', rationale: 'r', adjudicated_at: '2026-10-03T00:00:00.000Z', applied: false, ...adjudication }
    : null,
}) as unknown as Parameters<typeof evaluatePolicyEligibility>[1];

describe('curation policy adjudication agreement', () => {
  it('accepts the verified adjudication of the Curator', () => {
    expect(evaluatePolicyEligibility(policy, proposal('merge', { verified: true }), facts, false)).toBeNull();
  });

  it('ignores a decision recorded through the API, whatever agent it names', () => {
    expect(evaluatePolicyEligibility(policy, proposal('merge', { verified: false, agent_slug: 'opencti-curator' }), facts, false))
      .toBe(EXCLUSION_ADJUDICATION_MISSING);
    expect(evaluatePolicyEligibility(policy, proposal('merge', { agent_slug: 'opencti-curator' }), facts, false))
      .toBe(EXCLUSION_ADJUDICATION_MISSING);
  });

  it('refuses a verified adjudication that disagrees', () => {
    expect(evaluatePolicyEligibility(policy, proposal('merge', { verified: true, decision: 'distinct' }), facts, false))
      .toBe(EXCLUSION_ADJUDICATION_DISAGREES);
  });

  it('leaves to a human a merge proposal the Curator answered alias, whether agreement is required or not', () => {
    const aliasAnswer = proposal('merge', { verified: true, decision: 'alias' });
    expect(evaluatePolicyEligibility(policy, aliasAnswer, facts, false)).toBe(EXCLUSION_MANUAL_CHOICE);
    expect(evaluatePolicyEligibility({ ...policy, require_adjudication: false } as typeof policy, aliasAnswer, facts, false)).toBe(EXCLUSION_MANUAL_CHOICE);
  });

  it('applies an alias proposal only when the Curator answered alias, and leaves a merge answer to a human', () => {
    const aliasPolicy = { ...policy, policy_kinds: ['alias'] } as typeof policy;
    const aliasProposal = (decision: string) => ({ ...proposal('alias', { verified: true, decision: decision as CurationAdjudication['decision'] }), recommended_action: 'add_aliases' }) as ReturnType<typeof proposal>;
    expect(evaluatePolicyEligibility(aliasPolicy, aliasProposal('alias'), facts, false)).toBeNull();
    expect(evaluatePolicyEligibility(aliasPolicy, aliasProposal('distinct'), facts, false)).toBe(EXCLUSION_ADJUDICATION_DISAGREES);
    expect(evaluatePolicyEligibility(aliasPolicy, aliasProposal('merge'), facts, false)).toBe(EXCLUSION_MANUAL_CHOICE);
    expect(evaluatePolicyEligibility({ ...aliasPolicy, require_adjudication: false } as typeof policy, aliasProposal('merge'), facts, false)).toBe(EXCLUSION_MANUAL_CHOICE);
  });

  it('does not require an agreement for the kinds the Curator never adjudicates', () => {
    expect(evaluatePolicyEligibility(policy, proposal('stale', null), facts, false)).toBeNull();
  });
});

describe('curation policy access guardrails', () => {
  const aliasPolicy = { ...policy, policy_kinds: ['alias'], require_adjudication: false } as typeof policy;
  const aliasProposal = { ...proposal('alias', null), recommended_action: 'add_aliases' } as ReturnType<typeof proposal>;

  it('never adds an alias across different markings or organizations', () => {
    expect(evaluatePolicyEligibility(aliasPolicy, aliasProposal, facts, false)).toBeNull();
    expect(evaluatePolicyEligibility(aliasPolicy, aliasProposal, { ...facts, markingSets: [[], ['tlp-red']] }, false)).toBe(EXCLUSION_CROSS_MARKINGS);
    expect(evaluatePolicyEligibility(aliasPolicy, aliasProposal, { ...facts, organizationSets: [['org-a'], ['org-b']] }, false)).toBe(EXCLUSION_CROSS_ORGANIZATIONS);
  });
});

describe('curation policy source class', () => {
  const connectors = new Set(['connector-user']);

  it('classifies a subject from the source that created it, whoever updated it since', () => {
    expect(computeSourceClass([['connector-user', 'analyst']], connectors)).toBe('connector');
    expect(computeSourceClass([['analyst', 'connector-user']], connectors)).toBe('manual');
    expect(computeSourceClass([[]], connectors)).toBe('manual');
  });

  it('is mixed when the subjects were created by different source classes', () => {
    expect(computeSourceClass([['connector-user'], ['analyst']], connectors)).toBe('mixed');
  });
});
