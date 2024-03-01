import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { IndividualsLinesPaginationQuery, IndividualsLinesPaginationQuery$variables } from '@components/entities/individuals/__generated__/IndividualsLinesPaginationQuery.graphql';
import { IndividualsLines_data$key } from '@components/entities/individuals/__generated__/IndividualsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { IndividualLine, IndividualLineDummy } from './IndividualLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface IndividualsLinesProps {
  queryRef: PreloadedQuery<IndividualsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: IndividualsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const individualsLinesQuery = graphql`
  query IndividualsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: IndividualsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IndividualsLines_data
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

export const individualsLinesFragment = graphql`
  fragment IndividualsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IndividualsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IndividualsLinesRefetchQuery") {
    individuals(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_individuals") {
      edges {
        node {
          id
          name
          description
          ...IndividualLine_node
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

const IndividualsLines: FunctionComponent<IndividualsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IndividualsLinesPaginationQuery,
  IndividualsLines_data$key
  >({
    linesQuery: individualsLinesQuery,
    linesFragment: individualsLinesFragment,
    queryRef,
    nodePath: ['individuals', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.individuals?.edges ?? []}
      globalCount={
        data?.individuals?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={IndividualLine}
      DummyLineComponent={IndividualLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default IndividualsLines;
