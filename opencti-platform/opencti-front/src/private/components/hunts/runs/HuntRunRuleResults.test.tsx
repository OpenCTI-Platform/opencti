import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import HuntRunRuleResults from './HuntRunRuleResults';

vi.mock('react-relay', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-relay')>();
  return { ...original, useFragment: (_fragment: unknown, data: unknown) => data };
});

const result = (key: string, overrides: Record<string, unknown> = {}) => ({
  key,
  title: `Rule ${key}`,
  status: 'completed',
  hits_count: 0,
  truncated: false,
  first_hit_at: null,
  last_hit_at: null,
  error: null,
  ...overrides,
});

describe('Results per rule of a hunt run', () => {
  it('should count the rules with hits and the rules that failed, each rule on its own row', () => {
    const data = {
      id: 'run',
      rule_results: [
        result('a', { hits_count: 3 }),
        result('b'),
        result('c', { status: 'failed', error: 'The rule does not translate to SPL' }),
      ],
    };
    testRender(<HuntRunRuleResults data={data as never} />);
    expect(screen.getByTestId('hunt-run-rule-summary')).toHaveTextContent('1 of 3 rules found hits, 1 rule failed');
    const rows = screen.getAllByTestId('hunt-run-rule-row');
    expect(rows).toHaveLength(3);
    expect(rows[2]).toHaveAttribute('data-status', 'failed');
    expect(screen.getByTestId('hunt-run-rule-error')).toHaveTextContent('The rule does not translate to SPL');
  });

  it('should say a capped rule found at least its hits', () => {
    const data = { id: 'run', rule_results: [result('a', { hits_count: 500, truncated: true })] };
    testRender(<HuntRunRuleResults data={data as never} />);
    expect(screen.getByTestId('hunt-run-rule-row')).toHaveTextContent('At least 500');
  });

  it('should render nothing for a run without results per rule', () => {
    testRender(<HuntRunRuleResults data={{ id: 'run', rule_results: [] } as never} />);
    expect(screen.queryByTestId('hunt-run-rule-results')).not.toBeInTheDocument();
  });
});
