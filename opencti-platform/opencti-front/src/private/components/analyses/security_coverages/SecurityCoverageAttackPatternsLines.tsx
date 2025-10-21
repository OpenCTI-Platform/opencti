import React, { FunctionComponent } from 'react';
import { graphql, createRefetchContainer, RelayRefetchProp } from 'react-relay';
import { SecurityCoverageAttackPatternsLines_securityCoverage$data } from './__generated__/SecurityCoverageAttackPatternsLines_securityCoverage.graphql';
import EntityStixCoreRelationshipsRelationshipsView from '../../common/stix_core_relationships/views/EntityStixCoreRelationshipsRelationshipsView';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../components/list_lines';

const securityCoverageAttackPatternsLinesFragment = graphql`
  fragment SecurityCoverageAttackPatternsLines_securityCoverage on SecurityCoverage {
    id
    entity_type
  }
`;

interface SecurityCoverageAttackPatternsLinesProps {
  securityCoverage: SecurityCoverageAttackPatternsLines_securityCoverage$data;
  relay: RelayRefetchProp;
}

const SecurityCoverageAttackPatternsLinesComponent: FunctionComponent<SecurityCoverageAttackPatternsLinesProps> = ({
  securityCoverage,
}) => {
  const LOCAL_STORAGE_KEY = `SecurityCoverageAttackPatternsLines-${securityCoverage.id}`;

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<PaginationOptions>(
    LOCAL_STORAGE_KEY,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      filters: {
        mode: 'and',
        filters: [],
        filterGroups: [],
      },
      view: 'lines',
    },
  );

  return (
    <EntityStixCoreRelationshipsRelationshipsView
      entityId={securityCoverage.id}
      entityLink={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
      relationshipTypes={['has-covered']}
      stixCoreObjectTypes={['Attack-Pattern']}
      localStorage={{
        viewStorage,
        helpers,
        paginationOptions,
        localStorageKey: LOCAL_STORAGE_KEY,
      }}
      currentView="lines"
      enableContextualView={false}
      enableNestedView={false}
      allDirections={false}
      isRelationReversed={false}
      isCoverage={true}
      enableEntitiesView={false}
    />
  );
};

const SecurityCoverageAttackPatternsLines = createRefetchContainer(
  SecurityCoverageAttackPatternsLinesComponent,
  {
    securityCoverage: securityCoverageAttackPatternsLinesFragment,
  },
  graphql`
    query SecurityCoverageAttackPatternsLinesRefetchQuery(
      $id: String!
    ) {
      securityCoverage(id: $id) {
        ...SecurityCoverageAttackPatternsLines_securityCoverage
      }
    }
  `,
);

export default SecurityCoverageAttackPatternsLines;
