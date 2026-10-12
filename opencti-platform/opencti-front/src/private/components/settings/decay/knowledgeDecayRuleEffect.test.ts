import { createIntl } from 'react-intl';
import { describe, expect, it } from 'vitest';
import { knowledgeDecayRuleEffect } from './KnowledgeDecayRuleForm';

const intl = createIntl({ locale: 'en', messages: {}, onError: () => {} });
const labels: Record<string, string> = { entity_Malware: 'Malware', relationship_uses: 'uses', 'All relationships': 'All relationships' };
const t = (message: string, opts?: { values: Record<string, unknown> }) => {
  return labels[message] ?? intl.formatMessage({ id: message, defaultMessage: message }, opts?.values as Record<string, string>);
};

describe('knowledgeDecayRuleEffect', () => {
  it('states what the rule targets, after how long and what happens', () => {
    expect(knowledgeDecayRuleEffect(t, { target_scope: 'entity', target_types: ['Malware'], stale_after_days: 90, freshness_policy: 'flag' }))
      .toEqual('Malware not re-asserted within 90 days are flagged as stale.');
    expect(knowledgeDecayRuleEffect(t, { target_scope: 'relationship', target_types: ['uses'], stale_after_days: 1, freshness_policy: 'revoke' }))
      .toEqual('Uses relationships not re-asserted within 1 day are flagged as stale and revoked.');
    expect(knowledgeDecayRuleEffect(t, { target_scope: 'relationship', target_types: ['uses', 'targets'], stale_after_days: 7, freshness_policy: 'flag' }))
      .toEqual('Uses, relationship_targets relationships not re-asserted within 7 days are flagged as stale.');
    expect(knowledgeDecayRuleEffect(t, { target_scope: 'relationship', target_types: [], stale_after_days: 30, freshness_policy: 'lower_confidence' }))
      .toEqual('All relationships not re-asserted within 30 days are flagged as stale and their confidence is lowered.');
  });
});
