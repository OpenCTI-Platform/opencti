import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import {
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
  StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery$variables,
} from '@components/common/stix_domain_objects/__generated__/StixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery.graphql';
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
  const dataPreloaded = usePreloadedQuery(stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery, queryRef);
  const data = useFragment(stixDomainObjectAttackPatternsKillChainContainerFragment, dataPreloaded);
  // const data = usePreloadedPaginationFragment(
  //   {
  //     queryRef,
  //     linesQuery: stixDomainObjectAttackPatternsKillChainStixCoreRelationshipsQuery,
  //     linesFragment: stixDomainObjectAttackPatternsKillChainContainerFragment,
  //     nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
  //     setNumberOfElements: helpers.handleSetNumberOfElements,
  //   },
  // );
  console.log('data', data);
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
      handleToggleExports={disableExport ? null : helpers.handleToggleExports}
      openExports={openExports}
      availableFilterKeys={availableFilterKeys}
      refetch={refetch}
    />
  );
};

export default StixDomainObjectAttackPatternsKillChainContainer;
