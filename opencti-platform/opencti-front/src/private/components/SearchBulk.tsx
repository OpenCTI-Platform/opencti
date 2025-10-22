import React from 'react';
import { graphql } from 'react-relay';
import { SearchBulkQuery, SearchBulkQuery$variables } from './__generated__/SearchBulkQuery.graphql';
import { SearchBulkQuery_data$data } from './__generated__/SearchBulkQuery_data.graphql';
import { allEntitiesKeyList } from './common/bulk/utils/querySearchEntityByText';
import DataTable from '../../components/dataGrid/DataTable';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../components/dataGrid/dataTableTypes';

export const BULK_SEARCH_LOCAL_STORAGE_KEY = 'searchBulk';

export const searchBulkLineFragment = graphql`
  fragment SearchBulkLine_node on StixCoreObject {
    id
    entity_type
    created_at
    updated_at
    draftVersion {
      draft_id
      draft_operation
    }
    ... on StixObject {
      representative {
        main
        secondary
      }
    }
    ... on HashedObservable {
      hashes {
        algorithm
        hash
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

export const searchBulkQuery = graphql`
  query SearchBulkQuery(
    $count: Int!
    $cursor: ID
    $types: [String]
    $filters: FilterGroup
    $search: String
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
  ) {
    ...SearchBulkQuery_data
    @arguments(
      count: $count
      cursor: $cursor
      types: $types
      filters: $filters
      search: $search
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

export const searchBulkFragment = graphql`
  fragment SearchBulkQuery_data on Query
  @argumentDefinitions(
    count: { type: "Int", defaultValue: 500 }
    cursor: { type: "ID" }
    types: { type: "[String]" }
    search: { type: "String" }
    filters: { type: "FilterGroup" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: entity_type }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "SearchBulkRefetchQuery") {
    globalSearch(
      first: $count
      after: $cursor
      types: $types,
      search: $search,
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
    @connection(key: "Pagination_globalSearch") {
      edges {
        node {
          id
          entity_type
          ...SearchBulkLine_node
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

interface SearchBulkProps {
  inputValues: string[],
  dataColumns: DataTableProps['dataColumns'],
}

const SearchBulk = ({ inputValues, dataColumns }: SearchBulkProps) => {
  const buildSearchBulkFilters = (values: string[], filters: FilterGroup) => {
    return values.length > 0
      ? addFilter(filters, allEntitiesKeyList as unknown as string, values) // TODO INVALID TYPE
      : filters;
  };

  const initialValues = {
    sortBy: 'entity_type',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<SearchBulkQuery>(
    BULK_SEARCH_LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { filters } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);

  const queryFilters = buildSearchBulkFilters(inputValues, contextFilters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: queryFilters,
    count: 5000,
  } as SearchBulkQuery$variables;

  const queryRef = useQueryLoading<SearchBulkQuery>(searchBulkQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: searchBulkQuery,
    linesFragment: searchBulkFragment,
    queryRef,
    nodePath: ['globalSearch', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SearchBulkQuery>;

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: SearchBulkQuery_data$data) => data.globalSearch?.edges?.map((n) => n?.node)}
          storageKey={BULK_SEARCH_LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={queryFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          exportContext={{ entity_type: 'Stix-Core-Object' }}
          lineFragment={searchBulkLineFragment}
          hideSearch
          disableToolBar
          disableLineSelection
        />
      )}
    </>
  );
};

export default SearchBulk;
