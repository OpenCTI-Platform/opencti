import React from 'react';
import { useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  SearchStixCoreObjectsLinesPaginationQuery,
  SearchStixCoreObjectsLinesPaginationQuery$variables,
} from '@components/__generated__/SearchStixCoreObjectsLinesPaginationQuery.graphql';
import { SearchStixCoreObjectsLines_data$data } from '@components/__generated__/SearchStixCoreObjectsLines_data.graphql';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import useAuth from '../../utils/hooks/useAuth';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../utils/filters/filtersUtils';
import { decodeSearchKeyword } from '../../utils/SearchUtils';
import DataTable from '../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY = 'search';

const searchLineFragment = graphql`
  fragment SearchStixCoreObjectLine_node on StixCoreObject {
    id
    parent_types
    entity_type
    created_at
    ... on StixObject {
      representative {
        main
        secondary
      }
    }
    createdBy {
      ... on Identity {
        name
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
    containersNumber {
      total
    }
  }
`;

const searchStixCoreObjectsLinesQuery = graphql`
  query SearchStixCoreObjectsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SearchStixCoreObjectsLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const searchStixCoreObjectsLinesSearchQuery = graphql`
  query SearchStixCoreObjectsLinesSearchQuery(
    $types: [String]
    $filters: FilterGroup
    $search: String
  ) {
    stixCoreObjects(types: $types, search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          created_at
          updated_at
          ... on StixObject {
            representative {
              main
              secondary
            }
          }
          createdBy {
            ... on Identity {
              name
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
          containersNumber {
            total
          }
        }
      }
    }
  }
`;

export const searchStixCoreObjectsLinesFragment = graphql`
  fragment SearchStixCoreObjectsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SearchStixCoreObjectsLinesRefetchQuery") {
    globalSearch(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_globalSearch") {
      edges {
        node {
          id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              name
            }
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
          ...SearchStixCoreObjectLine_node
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

const Search = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { keyword } = useParams() as { keyword: string };

  const searchTerm = decodeSearchKeyword(keyword);

  const initialValues = {
    sortBy: '_score',
    orderAsc: false,
    openExports: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<SearchStixCoreObjectsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
    search: searchTerm,
  } as unknown as SearchStixCoreObjectsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<SearchStixCoreObjectsLinesPaginationQuery>(
    searchStixCoreObjectsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    entity_type: {
      label: 'Type',
      percentWidth: 10,
      isSortable: true,
    },
    value: {
      label: 'Value',
      percentWidth: 22,
      isSortable: false,
    },
    createdBy: {
      label: 'Author',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    creator: {
      label: 'Creator',
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      label: 'Labels',
      percentWidth: 16,
      isSortable: false,
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
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
  };

  const preloadedPaginationOptions = {
    linesQuery: searchStixCoreObjectsLinesQuery,
    linesFragment: searchStixCoreObjectsLinesFragment,
    queryRef,
    nodePath: ['globalSearch', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SearchStixCoreObjectsLinesPaginationQuery>;

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: SearchStixCoreObjectsLines_data$data) => data.globalSearch?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={searchLineFragment}
          preloadedPaginationProps={preloadedPaginationOptions}
          availableEntityTypes={['Stix-Core-Object']}
        />
      )}
    </>
  );
};

export default Search;
