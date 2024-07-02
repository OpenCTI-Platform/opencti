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
import StixDomainObjectAttackPatternsKillChain, { stixDomainObjectAttackPatternsKillChainQuery } from './StixDomainObjectAttackPatternsKillChain';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

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
}

const stixDomainObjectAttackPatternsKillChainContainerFragment = graphql`
    fragment StixDomainObjectAttackPatternsKillChainContainer_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        first: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "StixDomainObjectAttackPatternsKillChainRefetchQuery") {
        attackPatterns(
            search: $search
            first: $first
            after: $cursor
            filters: $filters
        ) @connection(key: "Pagination_attackPatterns") {
            edges {
                node {
                    id
                    parent_types
                    entity_type
                    name
                    description
                    x_mitre_id
                    x_mitre_platforms
                    x_mitre_permissions_required
                    x_mitre_detection
                    isSubAttackPattern
                    objectMarking {
                        id
                        definition_type
                        definition
                        x_opencti_order
                        x_opencti_color
                    }
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
                        phase_name
                        x_opencti_order
                    }
                }
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
}) => {
  const dataPreloaded = usePreloadedQuery<StixDomainObjectAttackPatternsKillChainQuery>(
    stixDomainObjectAttackPatternsKillChainQuery,
    queryRef,
  );
  const data = useFragment<StixDomainObjectAttackPatternsKillChainQuery$data>(
    stixDomainObjectAttackPatternsKillChainContainerFragment,
    dataPreloaded,
  ) as StixDomainObjectAttackPatternsKillChainContainer_data$data;
  return (
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
    />
  );
};

export default StixDomainObjectAttackPatternsKillChainContainer;
