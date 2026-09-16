import { describe, it, expect, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import SecurityCoverageInformation from './SecurityCoverageInformation';
import { screen } from '@testing-library/react';

vi.mock('./security_coverage_scores/SecurityCoverageScores', () => ({
  default: () => (<></>),
}));

describe('Component: SecurityCoverageInformation', () => {
  it('should display is covered : false and should not display the coverage scores section when there is no coverage_information', () => {
    testRender(
      <SecurityCoverageInformation
        coverage_information={undefined}
      />,
    );

    const isCovered = screen.queryByText('False');
    expect(isCovered).toBeInTheDocument();

    const section = screen.queryByText('Coverage scores');
    expect(section).not.toBeInTheDocument();
  });

  it('should display is covered : true and should display the coverage scores section when there is coverage_information', () => {
    const coverageInformationMock = [{
      coverage_name: 'name',
      coverage_score: 10,
    }];
    testRender(
      <SecurityCoverageInformation
        coverage_information={coverageInformationMock}
      />,
    );

    const isCovered = screen.queryByText('True');
    expect(isCovered).toBeInTheDocument();

    const section = screen.queryByText('Coverage scores');
    expect(section).toBeInTheDocument();
  });
});
