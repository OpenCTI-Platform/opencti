import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import SecurityCoverageMainInfo from './SecurityCoverageMainInfo';
import type { SecurityCoverageMainInfo_securityCoverage$key } from './__generated__/SecurityCoverageMainInfo_securityCoverage.graphql';

// useFragment is the identity: the tests give the component the fragment data directly.
vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useFragment: (_fragment: unknown, data: unknown) => data,
  };
});
vi.mock('./security_coverage_scores/SecurityCoverageScores', () => ({
  default: ({ coverage_information }: { coverage_information: ReadonlyArray<{ coverage_name: string; coverage_score: number }> }) => (
    <>{coverage_information.map((c) => `${c.coverage_name}:${c.coverage_score}`).join(',')}</>
  ),
}));

const buildData = (securityCoverageResults: unknown[]): SecurityCoverageMainInfo_securityCoverage$key => ({
  ' $fragmentType': 'SecurityCoverageMainInfo_securityCoverage',
  id: 'security-coverage-id',
  coverage_last_result: null,
  coverage_valid_from: null,
  coverage_valid_to: null,
  coverage_information: [{ coverage_name: 'detection', coverage_score: 50 }],
  results: securityCoverageResults,
} as unknown as SecurityCoverageMainInfo_securityCoverage$key);

const parisResult = {
  id: 'scr-paris',
  coverage_last_result: '2026-04-14T14:48:55.000Z',
  coverage_valid_from: '2026-04-14T14:48:55.000Z',
  coverage_valid_to: null,
  coverage_information: [{ coverage_name: 'detection', coverage_score: 80 }],
};
const emptyResult = {
  id: 'scr-empty',
  coverage_last_result: null,
  coverage_valid_from: null,
  coverage_valid_to: null,
  coverage_information: [],
};

describe('Component: SecurityCoverageMainInfo', () => {
  it('shows the coverage averages when no result is selected', () => {
    testRender(<SecurityCoverageMainInfo securityCoverage={buildData([parisResult])} selectedResultId={null} />);

    expect(screen.getByText('detection:50')).toBeInTheDocument();
  });

  it('shows the selected result scores and validity', () => {
    testRender(<SecurityCoverageMainInfo securityCoverage={buildData([parisResult])} selectedResultId="scr-paris" />);

    expect(screen.getByText('detection:80')).toBeInTheDocument();
    expect(screen.queryByText('detection:50')).not.toBeInTheDocument();
    // Valid from of the result: the dates of the coverage are null
    expect(screen.getAllByText(/2026/).length).toBeGreaterThan(0);
  });

  it('falls back to the averages when the selected result is unknown', () => {
    testRender(<SecurityCoverageMainInfo securityCoverage={buildData([parisResult])} selectedResultId="scr-gone" />);

    expect(screen.getByText('detection:50')).toBeInTheDocument();
  });

  it('shows no score for a selected result without coverage information', () => {
    testRender(<SecurityCoverageMainInfo securityCoverage={buildData([emptyResult])} selectedResultId="scr-empty" />);

    expect(screen.queryByText('detection:50')).not.toBeInTheDocument();
  });
});
