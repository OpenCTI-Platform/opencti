import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { MarkingDefinitionsLinesPaginationQuery, MarkingDefinitionsLinesPaginationQuery$variables } from '../__generated__/MarkingDefinitionsLinesPaginationQuery.graphql';
import { MarkingDefinitionsLines_data$key } from '../__generated__/MarkingDefinitionsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { MarkingDefinitionLine, MarkingDefinitionLineDummy } from './MarkingDefinitionLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';

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

interface MarkingDefinitionsLinesProps {
  dataColumns: DataColumns,
  queryRef: PreloadedQuery<MarkingDefinitionsLinesPaginationQuery>,
  paginationOptions: MarkingDefinitionsLinesPaginationQuery$variables,
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

const MarkingDefinitionsLines: FunctionComponent<MarkingDefinitionsLinesProps> = ({
  dataColumns,
  queryRef,
  paginationOptions,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<MarkingDefinitionsLinesPaginationQuery, MarkingDefinitionsLines_data$key>({
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
