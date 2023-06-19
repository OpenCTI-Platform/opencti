import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { tasksDataColumns, TasksLine, TasksLineDummy } from './TasksLine';
import {
  TasksLinesPaginationQuery,
  TasksLinesPaginationQuery$variables,
} from './__generated__/TasksLinesPaginationQuery.graphql';
import { TasksLine_node$data } from './__generated__/TasksLine_node.graphql';
import { TasksLines_data$key } from './__generated__/TasksLines_data.graphql';

const nbOfRowsToLoad = 50;

export const tasksLinesQuery = graphql`
  query TasksLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: TasksOrdering
    $orderMode: OrderingMode
    $filters: [TasksFiltering!]
  ) {
    ...TasksLines_data
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

const tasksLinesFragment = graphql`
  fragment TasksLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "TasksOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[TasksFiltering!]" }
  )
  @refetchable(queryName: "TasksLinesRefetchQuery") {
    tasks(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_tasks__tasks") {
      edges {
        node {
          ...TasksLine_node
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

interface TasksLinesProps {
  paginationOptions?: TasksLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<TasksLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, TasksLine_node$data>;
  deSelectedElements: Record<string, TasksLine_node$data>;
  onToggleEntity: (
    entity: TasksLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

const TasksLines: FunctionComponent<TasksLinesProps> = ({
  setNumberOfElements,
  queryRef,
  paginationOptions,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  TasksLinesPaginationQuery,
  TasksLines_data$key
  >({
    linesQuery: tasksLinesQuery,
    linesFragment: tasksLinesFragment,
    queryRef,
    nodePath: ['tasks', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataColumns={tasksDataColumns}
      dataList={data?.tasks?.edges ?? []}
      globalCount={data?.tasks?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={TasksLine}
      DummyLineComponent={TasksLineDummy}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default TasksLines;
