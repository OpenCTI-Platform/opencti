import React from 'react';
import { graphql } from 'react-relay';
import { TasksLinesPaginationQuery, TasksLinesPaginationQuery$variables } from '@components/cases/__generated__/TasksLinesPaginationQuery.graphql';
import { TasksLines_data$data } from '@components/cases/__generated__/TasksLines_data.graphql';
import { TasksLine_node$data } from '@components/cases/tasks/__generated__/TasksLine_node.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { TaskFragment } from './tasks/TasksLine';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import ItemDueDate from '../../../components/ItemDueDate';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';

const tasksLinesQuery = graphql`
  query TasksLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: TasksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
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
    filters: { type: "FilterGroup" }
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

export const LOCAL_STORAGE_KEY_TASKS = 'cases-casesTasks';

const Tasks = () => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<TasksLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_TASKS,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Task', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as TasksLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<TasksLinesPaginationQuery>(
    tasksLinesQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: { percentWidth: 35 },
    due_date: {
      label: 'Due Date',
      percentWidth: 15,
      isSortable: true,
      render: (task: TasksLine_node$data) => (
        <ItemDueDate due_date={task.due_date} variant={'inList'} />
      ),
    },
    objectAssignee: { percentWidth: 20 },
    objectLabel: { percentWidth: 20 },
    x_opencti_workflow_id: { percentWidth: 10 },
  };

  const preloadedPaginationProps = {
    linesQuery: tasksLinesQuery,
    linesFragment: tasksLinesFragment,
    queryRef,
    nodePath: ['tasks', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<TasksLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Tasks'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: TasksLines_data$data) => data.tasks?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY_TASKS}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={TaskFragment}
          exportContext={{ entity_type: 'Task' }}
        />
      )}
      {/* TODO Add task creation when it will be possible to assign a task to something
           <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <TaskCreation paginationOptions={paginationOptions} />
        </Security> */}
    </>
  );
};

export default Tasks;
