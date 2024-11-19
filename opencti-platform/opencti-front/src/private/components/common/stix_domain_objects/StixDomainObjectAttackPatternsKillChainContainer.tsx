import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import {
  StixDomainObjectAttackPatternsKillChainQuery,
  StixDomainObjectAttackPatternsKillChainQuery$data,
  StixDomainObjectAttackPatternsKillChainQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainQuery.graphql';
import { attackPatternsMatrixColumnsQuery } from '@components/techniques/attack_patterns/AttackPatternsMatrixColumns';
import { AttackPatternsMatrixColumnsQuery } from '@components/techniques/attack_patterns/__generated__/AttackPatternsMatrixColumnsQuery.graphql';
import StixDomainObjectAttackPatternsKillChain, { stixDomainObjectAttackPatternsKillChainQuery } from './StixDomainObjectAttackPatternsKillChain';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

interface StixDomainObjectAttackPatternsKillChainProps {
  helpers: UseLocalStorageHelpers;
  queryRef: PreloadedQuery<StixDomainObjectAttackPatternsKillChainQuery>;
  queryPaginationOptions: StixDomainObjectAttackPatternsKillChainQuery$variables;
  stixDomainObjectId: string;
  filters?: FilterGroup;
  searchTerm?: string;
  view?: string;
  defaultStartTime: string;
  defaultStopTime: string;
  disableExport: boolean;
  openExports?: boolean;
  availableFilterKeys: string[];
  storageKey: string;
}

export const stixDomainObjectAttackPatternsKillChainContainerLineFragment = graphql`
  fragment StixDomainObjectAttackPatternsKillChainContainerLine_node on AttackPattern {
    id
    parent_types
    entity_type
    name
    description
    x_mitre_id
    x_mitre_platforms
    x_mitre_permissions_required
    x_mitre_detection
    created
    modified
    objectLabel {
      id
      value
      color
    }
    isSubAttackPattern
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    killChainPhases {
      id
      kill_chain_name
      phase_name
      x_opencti_order
    }
  }
`;

export const stixDomainObjectAttackPatternsKillChainContainerFragment = graphql`
  fragment StixDomainObjectAttackPatternsKillChainContainer_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    first: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "AttackPatternsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "StixDomainObjectAttackPatternsKillChainRefetchQuery") {
    attackPatterns(
      search: $search
      first: $first
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_attackPatterns") {
      edges {
        node {
          id
          name
          description
          x_mitre_id
          ...StixDomainObjectAttackPatternsKillChainContainerLine_node
          isSubAttackPattern
          coursesOfAction {
            edges {
              node {
                id
                name
                description
                x_mitre_id
              }
            }
          }
          parentAttackPatterns {
            edges {
              node {
                id
                name
                description
                x_mitre_id
              }
            }
          }
          subAttackPatterns {
            edges {
              node {
                id
                name
                description
                x_mitre_id
              }
            }
          }
          killChainPhases {
            id
            kill_chain_name
            phase_name
            x_opencti_order
          }
          creators {
            id
            name
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const StixDomainObjectAttackPatternsKillChainContainer: FunctionComponent<StixDomainObjectAttackPatternsKillChainProps> = ({
  helpers,
  queryRef,
  queryPaginationOptions,
  stixDomainObjectId,
  filters,
  searchTerm,
  view,
  defaultStartTime,
  defaultStopTime,
  disableExport,
  openExports,
  availableFilterKeys,
  storageKey,
}) => {
  const dataPreloaded = usePreloadedQuery<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
    queryRef,
  );
  const data = useFragment<StixDomainObjectAttackPatternsKillChainQuery$data>(
    stixDomainObjectAttackPatternsKillChainContainerFragment,
    dataPreloaded,
  ) as StixDomainObjectAttackPatternsKillChainContainer_data$data;
  const killChainDataQueryRef = useQueryLoading<AttackPatternsMatrixColumnsQuery>(attackPatternsMatrixColumnsQuery);
  return killChainDataQueryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <StixDomainObjectAttackPatternsKillChain
        data={data}
        paginationOptions={queryPaginationOptions}
        stixDomainObjectId={stixDomainObjectId}
        handleChangeView={helpers.handleChangeView}
        handleSearch={helpers.handleSearch}
        helpers={helpers}
        filters={filters}
        searchTerm={searchTerm ?? ''}
        currentView={view}
        defaultStartTime={defaultStartTime}
        defaultStopTime={defaultStopTime}
        exportContext={{ entity_type: 'stix-core-relationship' }}
        handleToggleExports={disableExport ? undefined : helpers.handleToggleExports}
        openExports={openExports}
        availableFilterKeys={availableFilterKeys}
        storageKey={storageKey}
        killChainDataQueryRef={killChainDataQueryRef}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default StixDomainObjectAttackPatternsKillChainContainer;
