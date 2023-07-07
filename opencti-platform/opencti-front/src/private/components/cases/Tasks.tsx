import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import TasksLines, { tasksLinesQuery } from './tasks/TasksLines';
import { tasksDataColumns, TasksLineDummy } from './tasks/TasksLine';
import {
  TasksLinesPaginationQuery,
  TasksLinesPaginationQuery$variables,
} from './tasks/__generated__/TasksLinesPaginationQuery.graphql';
import { TasksLine_node$data } from './tasks/__generated__/TasksLine_node.graphql';

export const LOCAL_STORAGE_KEY_TASKS = 'view-cases-casesTasks';

const Tasks = () => {
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<TasksLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_TASKS,
    {
      numberOfElements: {
        number: 0,
        symbol: '',
      },
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: {} as Filters,
    },
  );
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<TasksLine_node$data>(LOCAL_STORAGE_KEY_TASKS);
  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;

    const queryRef = useQueryLoading<TasksLinesPaginationQuery>(
      tasksLinesQuery,
      paginationOptions,
    );
    return (
      <ListLines
        sortBy={sortBy}
        orderAsc={orderAsc}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleToggleExports={helpers.handleToggleExports}
        handleToggleSelectAll={handleToggleSelectAll}
        dataColumns={tasksDataColumns}
        selectAll={selectAll}
        openExports={openExports}
        exportEntityType="Task"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        iconExtension={true}
        availableFilterKeys={[
          'x_opencti_workflow_id',
          'assigneeTo',
          'participant',
          'markedBy',
          'labelledBy',
          'createdBy',
          'creator',
        ]}
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <TasksLineDummy key={idx} />
                    ))}
                </>
              }
            >
              <TasksLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
              />
            </React.Suspense>
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              handleClearSelectedElements={handleClearSelectedElements}
              selectAll={selectAll}
              filters={{
                entity_type: [{ id: 'Task', value: 'Task' }],
              }}
              type="Task"
            />
          </>
        )}
      </ListLines>
    );
  };
  return (
    <ExportContextProvider>
      {renderLines()}
      {/* TODO Add task creation when it will be possible to assign a task to something
           <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <TaskCreation paginationOptions={paginationOptions} />
        </Security> */}
    </ExportContextProvider>
  );
};

export default Tasks;
