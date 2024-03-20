import React from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import TasksLines, { tasksLinesQuery } from './tasks/TasksLines';
import { tasksDataColumns, TasksLineDummy } from './tasks/TasksLine';
import { TasksLinesPaginationQuery, TasksLinesPaginationQuery$variables } from './tasks/__generated__/TasksLinesPaginationQuery.graphql';
import { TasksLine_node$data } from './tasks/__generated__/TasksLine_node.graphql';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

export const LOCAL_STORAGE_KEY_TASKS = 'cases-casesTasks';

const Tasks = () => {
  const { t_i18n } = useFormatter();
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
      filters: emptyFilterGroup,
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

    const contextFilters = useBuildEntityTypeBasedFilterContext('Task', filters);
    const queryPaginationOptions = {
      ...paginationOptions,
      filters: contextFilters,
    } as unknown as TasksLinesPaginationQuery$variables;
    const queryRef = useQueryLoading<TasksLinesPaginationQuery>(
      tasksLinesQuery,
      queryPaginationOptions,
    );

    return (
      <ListLines
        helpers={helpers}
        sortBy={sortBy}
        orderAsc={orderAsc}
        handleSort={helpers.handleSort}
        handleSearch={helpers.handleSearch}
        handleAddFilter={helpers.handleAddFilter}
        handleRemoveFilter={helpers.handleRemoveFilter}
        handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={helpers.handleSwitchLocalMode}
        handleToggleExports={helpers.handleToggleExports}
        handleToggleSelectAll={handleToggleSelectAll}
        dataColumns={tasksDataColumns}
        selectAll={selectAll}
        openExports={openExports}
        exportContext={{ entity_type: 'Task' }}
        keyword={searchTerm}
        filters={filters}
        paginationOptions={queryPaginationOptions}
        numberOfElements={numberOfElements}
        iconExtension={true}
      >
        {queryRef && (
          <>
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <TasksLineDummy key={idx} />
                    ))}
                </>
              }
            >
              <TasksLines
                queryRef={queryRef}
                paginationOptions={queryPaginationOptions}
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
              filters={contextFilters}
              type="Task"
            />
          </>
        )}
      </ListLines>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Tasks'), current: true }]} />
      {renderLines()}
      {/* TODO Add task creation when it will be possible to assign a task to something
           <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Task'>
          <TaskCreation paginationOptions={paginationOptions} />
        </KnowledgeSecurity> */}
    </ExportContextProvider>
  );
};

export default Tasks;
