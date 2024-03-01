import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { GroupingLine, GroupingLineDummy } from './GroupingLine';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { GroupingLine_node$data } from './__generated__/GroupingLine_node.graphql';
import { GroupingsLinesPaginationQuery, GroupingsLinesPaginationQuery$variables } from './__generated__/GroupingsLinesPaginationQuery.graphql';
import { GroupingsLines_data$key } from './__generated__/GroupingsLines_data.graphql';

const nbOfRowsToLoad = 50;

export const groupingsLinesQuery = graphql`
  query GroupingsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: GroupingsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...GroupingsLines_data
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

const groupingsLineFragment = graphql`
  fragment GroupingsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "GroupingsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "GroupingsLinesRefetchQuery") {
    groupings(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_groupings") {
      edges {
        node {
          id
          name
          context
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...GroupingLine_node
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

interface GroupingsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: GroupingsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<GroupingsLinesPaginationQuery>;
  selectedElements: Record<string, GroupingLine_node$data>;
  deSelectedElements: Record<string, GroupingLine_node$data>;
  onToggleEntity: (
    entity: GroupingLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const GroupingsLines: FunctionComponent<GroupingsLinesProps> = ({
  paginationOptions,
  queryRef,
  dataColumns,
  onLabelClick,
  setNumberOfElements,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  GroupingsLinesPaginationQuery,
  GroupingsLines_data$key
  >({
    linesQuery: groupingsLinesQuery,
    linesFragment: groupingsLineFragment,
    queryRef,
    nodePath: ['groupings', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.groupings?.edges ?? []}
      globalCount={data?.groupings?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={GroupingLine}
      DummyLineComponent={GroupingLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default GroupingsLines;
