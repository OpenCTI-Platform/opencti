import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  AttackPatternsLinesPaginationQuery,
  AttackPatternsLinesPaginationQuery$variables,
} from '@components/techniques/attack_patterns/__generated__/AttackPatternsLinesPaginationQuery.graphql';
import { AttackPatternsLines_data$key } from '@components/techniques/attack_patterns/__generated__/AttackPatternsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { AttackPatternLine, AttackPatternLineDummy } from './AttackPatternLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface AttackPatternsLinesProps {
  queryRef: PreloadedQuery<AttackPatternsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: AttackPatternsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const attackPatternsLinesQuery = graphql`
  query AttackPatternsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...AttackPatternsLines_data
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

const attackPatternsLinesFragment = graphql`
  fragment AttackPatternsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "AttackPatternsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "AttackPatternsLinesRefetchQuery") {
    attackPatterns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_attackPatterns") {
      edges {
        node {
          name
          ...AttackPatternLine_node
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

const AttackPatternsLines: FunctionComponent<AttackPatternsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  AttackPatternsLinesPaginationQuery,
  AttackPatternsLines_data$key
  >({
    linesQuery: attackPatternsLinesQuery,
    linesFragment: attackPatternsLinesFragment,
    queryRef,
    nodePath: ['attackPatterns', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.attackPatterns?.edges ?? []}
      globalCount={
        data?.attackPatterns?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={AttackPatternLine}
      DummyLineComponent={AttackPatternLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default AttackPatternsLines;
