import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { RetentionLinesPaginationQuery, RetentionLinesPaginationQuery$variables } from '@components/settings/retention/__generated__/RetentionLinesPaginationQuery.graphql';
import { RetentionLines_data$key } from '@components/settings/retention/__generated__/RetentionLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { RetentionLine, RetentionLineDummy } from './RetentionLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

export const RetentionLinesQuery = graphql`
    query RetentionLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: RetentionRuleOrdering
        $orderMode: OrderingMode
    ) {
        ...RetentionLines_data
        @arguments(
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
        )
    }
`;

const retentionLinesFragment = graphql`
    fragment RetentionLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "RetentionRuleOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
    )
    @refetchable(queryName: "RetentionLinesQueryRefetchQuery") {
        retentionRules(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
        )
        @connection(key: "Pagination_retentionRules") {
            edges {
                node {
                    ...RetentionLine_node
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

interface RetentionLinesProps {
  dataColumns: DataColumns,
  paginationOptions: RetentionLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<RetentionLinesPaginationQuery>;
}

const RetentionLines: FunctionComponent<RetentionLinesProps> = ({
  dataColumns,
  paginationOptions,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  RetentionLinesPaginationQuery,
  RetentionLines_data$key
  >({
    linesQuery: RetentionLinesQuery,
    linesFragment: retentionLinesFragment,
    queryRef,
    nodePath: ['retentionRules', 'pageInfo', 'globalCount'],
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.retentionRules?.edges ?? []}
      globalCount={data?.retentionRules?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={RetentionLine}
      DummyLineComponent={RetentionLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default RetentionLines;
