import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useCopy from '../../../../utils/hooks/useCopy';
import useAuth, { UserContext } from '../../../../utils/hooks/useAuth';
import ExportContextProvider from '../../../../utils/ExportContextProvider';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { emptyFilterGroup, isFilterGroupNotEmpty, useGetDefaultFilterObject, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ContainerAddStixCoreObjectsInLine from './ContainerAddStixCoreObjectsInLine';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ContainerStixCyberObservables_container$data } from '@components/common/containers/__generated__/ContainerStixCyberObservables_container.graphql';
import { ContainerStixCyberObservablesLinesQuery$variables } from '@components/common/containers/__generated__/ContainerStixCyberObservablesLinesQuery.graphql';
import { ContainerStixCyberObservablesLinesSearchQuery$data } from '@components/common/containers/__generated__/ContainerStixCyberObservablesLinesSearchQuery.graphql';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { ContainerStixCyberObservablesLine_node$data } from '@components/common/containers/__generated__/ContainerStixCyberObservablesLine_node.graphql';
import {
  ContainerStixCyberObservablesLinesPaginationQuery,
  ContainerStixCyberObservablesLinesPaginationQuery$variables,
} from '@components/common/containers/__generated__/ContainerStixCyberObservablesLinesPaginationQuery.graphql';
import { ContainerStixCyberObservablesLines_data$data } from '@components/common/containers/__generated__/ContainerStixCyberObservablesLines_data.graphql';

const containerStixCyberObservableLineFragment = graphql`
    fragment ContainerStixCyberObservablesLine_node on StixCyberObservable {
        id
        entity_type
        observable_value
        created_at
        containersNumber {
            total
            count
        }
        createdBy {
            ... on Identity {
                id
                name
                entity_type
            }
        }
        objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
        }
        objectLabel {
            id
            value
            color
        }
        creators {
            id
            name
        }
    }
`;

export const ContainerStixCyberObservablesLinesSearchQuery = graphql`
  query ContainerStixCyberObservablesLinesSearchQuery(
    $id: String!
    $search: String
    $filters: FilterGroup
    $count: Int
  ) {
    container(id: $id) {
      id
      objects(
        search: $search
        first: $count
        filters: $filters
      ) {
        edges {
          node {
            ... on StixCyberObservable {
              id
              entity_type
              observable_value
              created_at
              createdBy {
                ... on Identity {
                  id
                  name
                  entity_type
                }
              }
              objectMarking {
                id
                definition_type
                definition
                x_opencti_order
                x_opencti_color
              }
              objectLabel {
                id
                value
                color
              }
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
  }
`;

export const containerStixCyberObservablesLinesFragment = graphql`
  fragment ContainerStixCyberObservablesLines_data on Query
  @argumentDefinitions(
    id: { type: "String!" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    types: { type: "[String]" }
    orderBy: { type: "StixObjectOrStixRelationshipsOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ContainerStixCyberObservablesLinesRefetchQuery") {
    container(id: $id) {
      id
      objects(
        types: $types
        search: $search
        first: $count
        after: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      ) @connection(key: "Pagination_objects") {
        edges {
          types
          node {
            ... on StixCyberObservable {
              id
              observable_value
              ...ContainerStixCyberObservablesLine_node
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
  }
`;

export const containerStixCyberObservablesLinesQuery = graphql`
  query ContainerStixCyberObservablesLinesPaginationQuery(
    $id: String!
    $search: String
    $count: Int
    $cursor: ID
    $types: [String]
    $orderBy: StixObjectOrStixRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ContainerStixCyberObservablesLines_data
      @arguments(
        id: $id
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

interface ContainerStixCyberObservablesComponentProps {
  container: ContainerStixCyberObservables_container$data;
  enableReferences?: boolean;
}

const ContainerStixCyberObservablesComponent: FunctionComponent<
  ContainerStixCyberObservablesComponentProps
> = ({ container, enableReferences }) => {
  const LOCAL_STORAGE_KEY = `container-${container.id}-stixCyberObservables`;
  const { platformModuleHelpers: { isRuntimeFieldEnable } } = useAuth();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Cyber-Observable']),
    },
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ContainerStixCyberObservablesLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      id: container.id,
      ...initialValues,
    },
  );
  const {
    filters,
    searchTerm,
  } = viewStorage;

  const {
    selectedElements,
    deSelectedElements,
    selectAll,
  } = useEntityToggle<ContainerStixCyberObservablesLine_node$data>(LOCAL_STORAGE_KEY);

  const getValuesForCopy = (
    data: ContainerStixCyberObservablesLinesSearchQuery$data,
  ) => {
    return (data.container?.objects?.edges ?? [])
      .map((o) => ({ id: o?.node.id, value: o?.node.observable_value }))
      .filter((o) => o.id) as { id: string; value: string }[];
  };

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Stix-Cyber-Observable']);
  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'objects',
        values: [container.id],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    types: ['Stix-Cyber-Observable'],
    filters: contextFilters,
  } as unknown as ContainerStixCyberObservablesLinesPaginationQuery$variables;

  const handleCopy = useCopy<ContainerStixCyberObservablesLinesSearchQuery$data>(
    {
      filters: contextFilters,
      searchTerm: searchTerm ?? '',
      query: ContainerStixCyberObservablesLinesSearchQuery,
      selectedValues: Object.values(selectedElements).map(
        ({ observable_value }) => observable_value ?? '',
      ),
      deselectedIds: Object.values(deSelectedElements).map((o) => o.id),
      elementId: container.id,
      getValuesForCopy,
    },
    selectAll,
  );

  const queryRef = useQueryLoading<ContainerStixCyberObservablesLinesPaginationQuery>(
    containerStixCyberObservablesLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: containerStixCyberObservablesLinesQuery,
    linesFragment: containerStixCyberObservablesLinesFragment,
    queryRef,
    nodePath: ['container', 'objects', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ContainerStixCyberObservablesLinesPaginationQuery>;
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: {
      label: 'Type',
      percentWidth: 12,
      isSortable: true,
    },
    observable_value: {
      label: 'Value',
      percentWidth: 28,
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      label: 'Labels',
      percentWidth: 19,
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    created_at: {
      label: 'Platform creation date',
      percentWidth: 10,
      isSortable: true,
    },
    analyses: {
      label: 'Analyses',
      percentWidth: 8,
      isSortable: false,
    },
    objectMarking: {
      label: 'Marking',
      percentWidth: 9,
      isSortable: isRuntimeSort,
    },
  };

  return (
    <div data-testid="container-observables-pages">
      <UserContext.Consumer>
        {() => (
          <ExportContextProvider>
            {queryRef && (
              <DataTable
                storageKey={LOCAL_STORAGE_KEY}
                initialValues={initialValues}
                lineFragment={containerStixCyberObservableLineFragment}
                preloadedPaginationProps={preloadedPaginationProps}
                resolvePath={(data: ContainerStixCyberObservablesLines_data$data) => data.container?.objects?.edges?.map((n) => n?.node)}
                dataColumns={dataColumns}
                contextFilters={contextFilters}
                handleCopy={handleCopy}
                exportContext={{ entity_id: container.id, entity_type: 'Stix-Cyber-Observable' }}
                availableEntityTypes={['Stix-Cyber-Observable']}
                searchContextFinal={{ entityTypes: ['Stix-Cyber-Observable'] }}
                createButton={(
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <ContainerAddStixCoreObjectsInLine
                      containerId={container.id}
                      targetStixCoreObjectTypes={['Stix-Cyber-Observable']}
                      containerStixCoreObjects={[...(container.objects?.edges ?? [])]}
                      paginationOptions={queryPaginationOptions}
                      enableReferences={enableReferences}
                    />
                  </Security>
                )}
              />
            )}
          </ExportContextProvider>
        )}
      </UserContext.Consumer>
    </div>
  );
};

const ContainerStixCyberObservables = createFragmentContainer(
  ContainerStixCyberObservablesComponent,
  {
    container: graphql`
      fragment ContainerStixCyberObservables_container on Container {
        id
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on Opinion {
          opinion
        }
        ... on ObservedData {
          name
          first_observed
          last_observed
        }
        ...ContainerHeader_container
        objects {
          edges {
            types
            node {
              ... on BasicObject {
                id
              }
            }
          }
        }
      }
    `,
  },
);

export default ContainerStixCyberObservables;
