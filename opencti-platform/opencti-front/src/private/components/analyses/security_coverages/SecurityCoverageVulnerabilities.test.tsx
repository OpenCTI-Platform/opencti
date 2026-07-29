import { describe, it, expect, vi } from 'vitest';
import React from 'react';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import SecurityCoverageVulnerabilities from './SecurityCoverageVulnerabilities';
import type { SecurityCoverageVulnerabilities_securityCoverage$key } from './__generated__/SecurityCoverageVulnerabilities_securityCoverage.graphql';

vi.mock('../../common/stix_core_relationships/StixCoreRelationshipPopover', () => ({
  default: () => (<></>),
}));
vi.mock('./SecurityCoverageScores', () => ({
  default: () => (<></>),
}));
// jsdom reports zero size, so react-virtualized's AutoSizer would render no rows.
// Provide a fixed width so the virtualized list mounts its rows during tests.
vi.mock('react-virtualized', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-virtualized')>();
  return {
    ...actual,
    AutoSizer: ({ children }: { children: (size: { width: number; height: number }) => React.ReactNode }) => children({ width: 1000, height: 570 }),
  };
});

const buildData = (globalCount: number): SecurityCoverageVulnerabilities_securityCoverage$key => ({
  ' $fragmentType': 'SecurityCoverageVulnerabilities_securityCoverage',
  id: 'security-coverage-id',
  name: 'SC',
  parent_types: [],
  entity_type: 'Security-Coverage',
  vulnerabilities: {
    count: globalCount,
    entities: [
      {
        relationship_id: 'relationship-id',
        coverage_information: [],
        to: {
          id: 'vulnerability-id',
          parent_types: [],
          name: 'Vuln1',
          description: '',
        },
      },
    ],
  },
} as unknown as SecurityCoverageVulnerabilities_securityCoverage$key);

describe('Component: SecurityCoverageVulnerabilities', () => {
  it('should not display a warning when the count is under the fetch cap', () => {
    testRender(
      <SecurityCoverageVulnerabilities securityCoverage={buildData(2)} />,
    );

    expect(screen.getByText('Vulnerabilities')).toBeInTheDocument();
    expect(screen.getByText('Vuln1')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('should display a warning when there are more vulnerabilities than the fetch cap', () => {
    testRender(
      <SecurityCoverageVulnerabilities securityCoverage={buildData(5001)} />,
    );

    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Showing 5000 of 5001 vulnerabilities. Some results are not displayed.')).toBeInTheDocument();
  });

  it('should merge the same vulnerability covered by several results into a single row', () => {
    const data = {
      ' $fragmentType': 'SecurityCoverageVulnerabilities_securityCoverage',
      id: 'security-coverage-id',
      name: 'SC',
      parent_types: [],
      entity_type: 'Security-Coverage',
      vulnerabilities: {
        count: 2,
        entities: [
          {
            relationship_id: 'relationship-1',
            coverage_information: [{ coverage_name: 'Prevention', coverage_score: 40 }],
            to: { id: 'vulnerability-id', parent_types: [], name: 'Vuln1', description: '' },
          },
          {
            relationship_id: 'relationship-2',
            coverage_information: [{ coverage_name: 'Prevention', coverage_score: 60 }],
            to: { id: 'vulnerability-id', parent_types: [], name: 'Vuln1', description: '' },
          },
        ],
      },
    } as unknown as SecurityCoverageVulnerabilities_securityCoverage$key;

    testRender(
      <SecurityCoverageVulnerabilities securityCoverage={data} />,
    );

    expect(screen.getAllByText('Vuln1')).toHaveLength(1);
  });
});
