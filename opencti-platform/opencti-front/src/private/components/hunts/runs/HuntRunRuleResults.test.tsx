import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import HuntRunRuleResults from './HuntRunRuleResults';

vi.mock('react-relay', async (importOriginal) => {
  const original = await importOriginal<typeof import('react-relay')>();
  return { ...original, useFragment: (_fragment: unknown, data: unknown) => data };
});

// The data table reads the metrics and the links of the platform, which the application provides
vi.mock('../../../../utils/hooks/useAppData', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../utils/hooks/useAppData')>();
  return { ...original, useAppData: () => ({ metricsDefinition: [], computeLink: () => undefined }), useComputeLink: () => () => undefined };
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
  // The table keeps its sort in the local storage of the run
  afterEach(() => localStorage.clear());

  it('should count the rules with hits and the rules that failed, each rule on its own row, the most hits first', () => {
    const data = {
      id: 'run',
      rule_results: [
        result('c', { status: 'failed', error: 'The rule does not translate to SPL' }),
        result('b'),
        result('a', { hits_count: 3 }),
      ],
    };
    testRender(<HuntRunRuleResults data={data as never} />);
    expect(screen.getByTestId('hunt-run-rule-summary')).toHaveTextContent('1 of 3 rules found hits, 1 rule failed');
    const rows = screen.getAllByTestId('hunt-run-rule-row');
    expect(rows.map((row) => row.textContent)).toEqual(['Rule a', 'Rule b', expect.stringContaining('Rule c')]);
    // A failed rule has no hit count: it comes last, its error under its title
    expect(rows[2]).toHaveAttribute('data-status', 'failed');
    expect(rows[2]).toHaveTextContent('Failed');
    expect(within(rows[2]).getByTestId('hunt-run-rule-error')).toHaveTextContent('The rule does not translate to SPL');
    const headers = within(screen.getByTestId('hunt-run-rule-table')).getAllByRole('columnheader');
    expect(headers.map((header) => header.getAttribute('aria-sort'))).toEqual(['none', 'descending', 'none', 'none']);
  });

  it('should say a capped rule found at least its hits', () => {
    const data = { id: 'run', rule_results: [result('a', { hits_count: 500, truncated: true })] };
    testRender(<HuntRunRuleResults data={data as never} />);
    expect(within(screen.getByTestId('hunt-run-rule-table')).getByRole('row')).toHaveTextContent('At least 500');
  });

  it('should render nothing for a run without results per rule', () => {
    testRender(<HuntRunRuleResults data={{ id: 'run', rule_results: [] } as never} />);
    expect(screen.queryByTestId('hunt-run-rule-results')).not.toBeInTheDocument();
  });
});
