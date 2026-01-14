import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { IngestionCsvLinesPaginationQuery, IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvLines_data$key } from '@components/data/ingestionCsv/__generated__/IngestionCsvLines_data.graphql';
import { IngestionCsvLineComponent, IngestionCsvLineDummy, IngestionCsvLineProps } from '@components/data/ingestionCsv/IngestionCsvLine';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

interface IngestionCsvLinesProps {
  queryRef: PreloadedQuery<IngestionCsvLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onOpenHistory: (ingestionId: string) => void;
}

export const ingestionCsvLinesQuery = graphql`
  query IngestionCsvLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IngestionCsvOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IngestionCsvLines_data
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

const ingestionCsvLinesFragment = graphql`
  fragment IngestionCsvLines_data on Query 
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IngestionCsvOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters:{ type: "FilterGroup" }
  )
  @refetchable(queryName: "IngestionCsvLinesRefetchQuery") {
    ingestionCsvs(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_ingestionCsvs") {
      edges {
        node {
          id
          ...IngestionCsvLine_node
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

const IngestionCsvLines: FunctionComponent<IngestionCsvLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
  setNumberOfElements,
  onOpenHistory,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
    IngestionCsvLinesPaginationQuery,
    IngestionCsvLines_data$key
  >({
    linesQuery: ingestionCsvLinesQuery,
    linesFragment: ingestionCsvLinesFragment,
    queryRef,
    nodePath: ['ingestionCsvs', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  const { ingestionCsvs } = data;

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={ingestionCsvs?.edges ?? []}
      globalCount={ingestionCsvs?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={(props: IngestionCsvLineProps) => (
        <IngestionCsvLineComponent {...props} onOpenHistory={onOpenHistory} />
      )}
      DummyLineComponent={IngestionCsvLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default IngestionCsvLines;
