import { describe, it, expect, vi } from 'vitest';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { StixCoreRelationshipEditionOverviewComponent } from './StixCoreRelationshipEditionOverview';
import { screen } from '@testing-library/react';
import { StixCoreRelationshipEditionOverview_stixCoreRelationship$data } from './__generated__/StixCoreRelationshipEditionOverview_stixCoreRelationship.graphql';

vi.mock('../../../../utils/hooks/useFormEditor', () => ({
  default: () => ({
    fieldPatch: vi.fn(),
    changeFocus: vi.fn(),
    changeField: vi.fn(),
    changeKillChainPhases: vi.fn(),
    changeCreated: vi.fn(),
    changeMarking: vi.fn(),
  }),
}));

describe('Component: StixCoreRelationshipEditionOverviewComponent', () => {
  const userContext = createMockUserContext({
    entitySettings: { edges: [] },
  });

  const relationship = (relationshipType: string) => {
    return {
      relationship_type: relationshipType,
      coverage_information: [],
      editContext: [],
    } as unknown as StixCoreRelationshipEditionOverview_stixCoreRelationship$data;
  };

  it('should display Coverage Information if isCoverage is true and relationship is not has-covered', () => {
    testRender(
      <StixCoreRelationshipEditionOverviewComponent
        isCoverage={true}
        stixCoreRelationship={relationship('targets')}
        handleClose={vi.fn()}
        noStoreUpdate
      />,
      { userContext },
    );

    const coverageEdition = screen.queryByText('Coverage Information');
    expect(coverageEdition).toBeInTheDocument();
  });

  it('should display Coverage Information if isCoverage is false and relationship is has-covered', () => {
    testRender(
      <StixCoreRelationshipEditionOverviewComponent
        isCoverage={false}
        stixCoreRelationship={relationship('has-covered')}
        handleClose={vi.fn()}
        noStoreUpdate
      />,
      { userContext },
    );

    const coverageEdition = screen.queryByText('Coverage Information');
    expect(coverageEdition).toBeInTheDocument();
  });

  it('should not display Coverage Information if isCoverage is false and relationship is not has-covered', () => {
    testRender(
      <StixCoreRelationshipEditionOverviewComponent
        isCoverage={false}
        stixCoreRelationship={relationship('targets')}
        handleClose={vi.fn()}
        noStoreUpdate
      />,
      { userContext },
    );

    const coverageEdition = screen.queryByText('Coverage Information');
    expect(coverageEdition).not.toBeInTheDocument();
  });
});
