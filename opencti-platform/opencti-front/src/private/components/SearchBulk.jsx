import React from 'react';
import { graphql } from 'react-relay';
import { allEntitiesKeyList } from './common/bulk/utils/querySearchEntityByText';
import DataTable from '../../components/dataGrid/DataTable';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../utils/hooks/useQueryLoading';

const LOCAL_STORAGE_KEY = 'search_bulk';

const searchBulkLineFragment = graphql`
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

const buildQueryParams = (textFieldValue, filters) => {
  const values = textFieldValue
    .split('\n')
    .filter((o) => o.length > 1)
    .map((val) => val.trim());
  const queryFilters = values.length > 0
    ? addFilter(filters, allEntitiesKeyList, values)
    : filters;
  return { values, queryFilters, count: 5000 };
};

const SearchBulk = ({ textFieldValue, dataColumns }) => {
  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const { filters } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', filters);

  const { values, queryFilters, count } = buildQueryParams(textFieldValue, contextFilters);

  const queryPaginationOptions = { ...paginationOptions, filters: queryFilters, count };

  const queryRef = useQueryLoading(searchBulkQuery, queryPaginationOptions);

  const preloadedPaginationProps = {
    linesQuery: searchBulkQuery,
    linesFragment: searchBulkFragment,
    queryRef,
    nodePath: ['globalSearch', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  };

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.globalSearch?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={queryFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          exportContext={{ entity_type: 'Stix-Core-Object' }}
          paginationOptions={queryPaginationOptions}
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
