import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import {
  ExclusionListsLinesPaginationQuery,
  ExclusionListsLinesPaginationQuery$variables,
} from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import { ExclusionListsLines_data$key } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLines_data.graphql';
import { ExclusionListsLine, ExclusionListsLineDummy } from '@components/settings/exclusion_lists/ExclusionListsLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

export const exclusionListsLinesQuery = graphql`
  query ExclusionListsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ExclusionListOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ExclusionListsLines_data
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

export const exclusionListsLinesFragment = graphql`
  fragment ExclusionListsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ExclusionListOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "ExclusionListsLinesRefetchQuery") {
    exclusionLists(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_exclusionLists") {
      edges {
        node {
          ...ExclusionListsLine_node
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

export interface ExclusionListsLinesProps {
  paginationOptions: ExclusionListsLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<ExclusionListsLinesPaginationQuery>;
}

const ExclusionListsLines: FunctionComponent<ExclusionListsLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ExclusionListsLinesPaginationQuery,
  ExclusionListsLines_data$key
  >({
    queryRef,
    linesQuery: exclusionListsLinesQuery,
    linesFragment: exclusionListsLinesFragment,
    nodePath: ['exclusionLists', 'pageInfo', 'globalCount'],
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.exclusionLists?.edges ?? []}
      globalCount={data?.exclusionLists?.pageInfo?.globalCount}
      LineComponent={ExclusionListsLine}
      DummyLineComponent={ExclusionListsLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default ExclusionListsLines;
