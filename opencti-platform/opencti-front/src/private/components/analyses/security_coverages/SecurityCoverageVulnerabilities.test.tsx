import { describe, it, expect, vi } from 'vitest';
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

const buildData = (globalCount: number): SecurityCoverageVulnerabilities_securityCoverage$key => ({
  ' $fragmentType': 'SecurityCoverageVulnerabilities_securityCoverage',
  id: 'security-coverage-id',
  name: 'SC',
  parent_types: [],
  entity_type: 'Security-Coverage',
  vulnerabilities: {
    pageInfo: { globalCount },
    edges: [
      {
        node: {
          id: 'relationship-id',
          coverage_information: [],
          to: {
            id: 'vulnerability-id',
            parent_types: [],
            name: 'Vuln1',
            description: '',
          },
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
      <SecurityCoverageVulnerabilities securityCoverage={buildData(501)} />,
    );

    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText('Showing 500 of 501 vulnerabilities. Some results are not displayed.')).toBeInTheDocument();
  });
});
