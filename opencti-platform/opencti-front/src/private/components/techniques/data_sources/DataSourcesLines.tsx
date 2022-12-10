import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UseLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataSourceLineComponent, DataSourceLineDummy } from './DataSourceLine';
import {
  DataSourcesLinesPaginationQuery,
  DataSourcesLinesPaginationQuery$variables,
} from './__generated__/DataSourcesLinesPaginationQuery.graphql';
import { DataSourcesLines_data$key } from './__generated__/DataSourcesLines_data.graphql';

const nbOfRowsToLoad = 50;

interface DataSourceLinesProps {
  queryRef: PreloadedQuery<DataSourcesLinesPaginationQuery>,
  dataColumns: DataColumns,
  paginationOptions?: DataSourcesLinesPaginationQuery$variables,
  setNumberOfElements: UseLocalStorage[2]['handleSetNumberOfElements'],
  onLabelClick: (k: string, id: string, value: Record<string, unknown>, event: React.KeyboardEvent) => void,
}

export const dataSourcesLinesQuery = graphql`
  query DataSourcesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DataSourcesOrdering
    $orderMode: OrderingMode
    $filters: [DataSourcesFiltering!]
  ) {
    ...DataSourcesLines_data @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const dataSourcesLinesFragment = graphql`
  fragment DataSourcesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DataSourcesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[DataSourcesFiltering!]" }
  ) @refetchable(queryName: "DataSourcesLinesRefetchQuery") {
    dataSources(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_dataSources") {
      edges {
        node {
          id
          name
          description
          ...DataSourceLine_node
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

const DataSourcesLines: FunctionComponent<DataSourceLinesProps> = ({ setNumberOfElements, queryRef, dataColumns, paginationOptions, onLabelClick }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<DataSourcesLinesPaginationQuery, DataSourcesLines_data$key>({
    linesQuery: dataSourcesLinesQuery,
    linesFragment: dataSourcesLinesFragment,
    queryRef,
    nodePath: ['dataSources', 'edges'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.dataSources?.edges ?? []}
      globalCount={data?.dataSources?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={ DataSourceLineComponent }
      DummyLineComponent={ DataSourceLineDummy }
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default DataSourcesLines;
