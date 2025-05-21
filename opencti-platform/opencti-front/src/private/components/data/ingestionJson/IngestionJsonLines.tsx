import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { IngestionJsonLineComponent, IngestionJsonLineDummy } from '@components/data/ingestionJson/IngestionJsonLine';
import {
  IngestionJsonLinesPaginationQuery,
  IngestionJsonLinesPaginationQuery$variables,
} from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { IngestionJsonLines_data$key } from '@components/data/ingestionJson/__generated__/IngestionJsonLines_data.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

interface IngestionJsonLinesProps {
  queryRef: PreloadedQuery<IngestionJsonLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const ingestionJsonLinesQuery = graphql`
  query IngestionJsonLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IngestionJsonOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IngestionJsonLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const ingestionJsonLinesFragment = graphql`
  fragment IngestionJsonLines_data on Query 
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IngestionJsonOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters:{ type: "FilterGroup" }
  )
  @refetchable(queryName: "IngestionJsonLinesRefetchQuery") {
    ingestionJsons(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_ingestionJsons") {
      edges {
        node {
          id
          ...IngestionJsonLine_node
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

const IngestionJsonLines: FunctionComponent<IngestionJsonLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IngestionJsonLinesPaginationQuery,
  IngestionJsonLines_data$key>({
    queryRef,
    linesQuery: ingestionJsonLinesQuery,
    linesFragment: ingestionJsonLinesFragment,
    nodePath: ['ingestionJsons', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  const ingestionJsons = data?.ingestionJsons?.edges ?? [];
  const globalCount = data?.ingestionJsons?.pageInfo?.globalCount;
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={ingestionJsons}
      globalCount={globalCount ?? nbOfRowsToLoad}
      LineComponent={IngestionJsonLineComponent}
      DummyLineComponent={IngestionJsonLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default IngestionJsonLines;
