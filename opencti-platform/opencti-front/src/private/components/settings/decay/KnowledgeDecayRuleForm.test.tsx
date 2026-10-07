import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import type { UserContextType } from '../../../../utils/hooks/useAuth';
import KnowledgeDecayRuleForm from './KnowledgeDecayRuleForm';

vi.mock('@components/common/lists/Filters', () => ({
  default: () => <div data-testid="filters" />,
}));
vi.mock('../../../../components/FilterIconButton', () => ({
  default: () => <div data-testid="filter-icon-button" />,
}));

const userContext = createMockUserContext({
  schema: { scrs: [{ id: 'uses' }], sdos: [{ id: 'Infrastructure' }], scos: [{ id: 'IPv4-Addr' }] } as unknown as UserContextType['schema'],
});

const renderForm = (targetScope: 'relationship' | 'entity', policy: 'flag' | 'lower_confidence' = 'lower_confidence') => testRender(
  <KnowledgeDecayRuleForm
    initialValues={{ target_scope: targetScope, freshness_policy: policy }}
    onSubmit={vi.fn()}
    onCancel={vi.fn()}
  />,
  { userContext },
);

describe('Knowledge decay rule form', () => {
  it('should explain every field of the rule', () => {
    renderForm('relationship');
    [
      'The knowledge the rule ages: relationships, for example uses, or entities, for example infrastructures. Indicators keep their own decay rules.',
      'Leave empty to apply the rule to every relationship and sighting.',
      'Days without any assertion after which the knowledge is stale, for example 180. A source creating or updating the knowledge again is an assertion.',
      'Flag as stale only marks the knowledge. Lower the confidence also lowers its confidence by the confidence step. Revoke also revokes it, for the types that can be revoked.',
      'Points removed from the confidence, from 1 to 100, once each time the knowledge becomes stale.',
      'When rules overlap, the rule with the highest order applies to the knowledge they share; the others leave it alone.',
      'An inactive rule ages nothing, and the knowledge it flagged is no longer stale.',
    ].forEach((help) => expect(screen.getByText(help)).toBeInTheDocument());
  });

  it('should say that an entity rule needs at least one entity type', () => {
    renderForm('entity', 'flag');
    expect(screen.getByText('At least one entity type, for example Infrastructure.')).toBeInTheDocument();
    expect(screen.queryByText('Points removed from the confidence, from 1 to 100, once each time the knowledge becomes stale.')).not.toBeInTheDocument();
  });

  it('should link to the documentation of knowledge decay rules', () => {
    renderForm('relationship');
    expect(screen.getByRole('link', { name: 'Learn more about knowledge decay rules' }))
      .toHaveAttribute('href', 'https://docs.opencti.io/latest/administration/decay-rules/#knowledge-decay-rules');
  });
});
