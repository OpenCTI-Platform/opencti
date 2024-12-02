import React from 'react';
import { graphql } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { MarkingDefinitionLine, MarkingDefinitionLineDummy } from './MarkingDefinitionLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

export const markingDefinitionsLinesQuery = graphql`
    query MarkingDefinitionsLinesPaginationQuery(
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: MarkingDefinitionsOrdering
        $orderMode: OrderingMode
    ) {
        ...MarkingDefinitionsLines_data
        @arguments(
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
        )
    }
`;

const markingDefinitionsLinesFragment = graphql`
    fragment MarkingDefinitionsLines_data on Query
    @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
            type: "MarkingDefinitionsOrdering"
            defaultValue: definition
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
    )
    @refetchable(queryName: "MarkingDefinitionsLinesRefetchQuery") {
        markingDefinitions(
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
        ) @connection(key: "Pagination_markingDefinitions") {
            edges {
                node {
                    ...MarkingDefinitionLine_node
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

export const markingDefinitionsLinesSearchQuery = graphql`
  query MarkingDefinitionsLinesSearchQuery($search: String, $filters: FilterGroup, $first: Int) {
    markingDefinitions(search: $search, filters: $filters, first: $first) {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_color
          x_opencti_order
        }
      }
    }
  }
`;

const MarkingDefinitionsLines = ({
  dataColumns,
  queryRef,
  paginationOptions,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment({
    linesQuery: markingDefinitionsLinesQuery,
    linesFragment: markingDefinitionsLinesFragment,
    queryRef,
    nodePath: ['markingDefinitions', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.markingDefinitions?.edges ?? []}
      globalCount={data?.markingDefinitions?.pageInfo.globalCount ?? nbOfRowsToLoad}
      LineComponent={MarkingDefinitionLine}
      DummyLineComponent={MarkingDefinitionLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default MarkingDefinitionsLines;
