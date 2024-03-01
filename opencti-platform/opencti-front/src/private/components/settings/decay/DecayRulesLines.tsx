import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { DecayRulesLines_data$key } from '@components/settings/decay/__generated__/DecayRulesLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';
import { DecayRulesLine, DecayRulesLineDummy } from './DecayRulesLine';
import { DecayRulesLinesPaginationQuery, DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';

const nbOfRowsToLoad = 50;

export const decayRulesLinesQuery = graphql`
  query DecayRulesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: DecayRuleOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DecayRulesLines_data
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
export const decayRulesLinesFragment = graphql`
  fragment DecayRulesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DecayRuleOrdering", defaultValue: order }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "DecayRulesLinesRefetchQuery") {
    decayRules(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_decayRules") {
      edges {
        node {
          ...DecayRulesLine_node
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

export interface DecayRulesLinesProps {
  paginationOptions: DecayRulesLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<DecayRulesLinesPaginationQuery>;
}
const DecayRulesLines: FunctionComponent<DecayRulesLinesProps> = ({
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  DecayRulesLinesPaginationQuery,
  DecayRulesLines_data$key
  >({
    queryRef,
    linesQuery: decayRulesLinesQuery,
    linesFragment: decayRulesLinesFragment,
    nodePath: ['decayRules', 'pageInfo', 'globalCount'],
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.decayRules?.edges ?? []}
      globalCount={data?.decayRules?.pageInfo?.globalCount}
      LineComponent={DecayRulesLine}
      DummyLineComponent={DecayRulesLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default DecayRulesLines;
