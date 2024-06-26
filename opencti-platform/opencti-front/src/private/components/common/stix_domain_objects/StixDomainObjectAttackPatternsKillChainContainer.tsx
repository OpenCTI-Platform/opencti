import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import {
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$data,
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery.graphql';
import {
  StixDomainObjectAttackPatternsKillChainContainer_data$data,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainContainer_data.graphql';
import StixDomainObjectAttackPatternsKillChain, { stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery } from './StixDomainObjectAttackPatternsKillChain';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

interface StixDomainObjectAttackPatternsKillChainProps {
  helpers: UseLocalStorageHelpers;
  queryRef: PreloadedQuery<StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery>;
  entityLink: string;
  queryPaginationOptions: StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables;
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
    fragment StixDomainObjectAttackPatternsKillChainContainer_data on Query {
        stixCoreRelationships(
            fromOrToId: $fromOrToId
            elementWithTargetTypes: $elementWithTargetTypes
            first: $first
            filters: $filters
        ) @connection(key: "Pagination_stixCoreRelationships") {
            edges {
                node {
                    id
                    description
                    start_time
                    stop_time
                    from {
                        ... on BasicRelationship {
                            id
                            entity_type
                        }
                        ... on AttackPattern {
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
                    to {
                        ... on BasicRelationship {
                            id
                            entity_type
                        }
                        ... on AttackPattern {
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
                    killChainPhases {
                        id
                        phase_name
                        x_opencti_order
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
        }
    }
`;

const StixDomainObjectAttackPatternsKillChainContainer: FunctionComponent<StixDomainObjectAttackPatternsKillChainProps> = ({
  helpers,
  queryRef,
  entityLink,
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
  const dataPreloaded = usePreloadedQuery<StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery>(
    stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
    queryRef,
  );
  const data = useFragment<StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$data>(
    stixDomainObjectAttackPatternsKillChainContainerFragment,
    dataPreloaded,
  ) as StixDomainObjectAttackPatternsKillChainContainer_data$data;
  const refetch = React.useCallback;
  return (
    <StixDomainObjectAttackPatternsKillChain
      data={data}
      entityLink={entityLink}
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
      refetch={refetch}
    />
  );
};

export default StixDomainObjectAttackPatternsKillChainContainer;
