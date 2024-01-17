import React from 'react';
import { makeStyles } from '@mui/styles';
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
import { buildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import type { Theme } from '../../../components/Theme';
import BreadcrumbHeader from '../../../components/BreadcrumbHeader';
import { useFormatter } from '../../../components/i18n';

export const LOCAL_STORAGE_KEY_TASKS = 'cases-casesTasks';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
}));

const Tasks = () => {
  const classes = useStyles();
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

    const contextFilters = buildEntityTypeBasedFilterContext('Task', filters);
    const queryPaginationOptions = {
      ...paginationOptions,
      filters: contextFilters,
    } as unknown as TasksLinesPaginationQuery$variables;
    const queryRef = useQueryLoading<TasksLinesPaginationQuery>(
      tasksLinesQuery,
      queryPaginationOptions,
    );

    return (
      <>
        <BreadcrumbHeader
          path={[
            { text: t_i18n('Cases') },
            { text: t_i18n('Tasks') },
          ]}
        >
          <div className={ classes.header }>{t_i18n('Tasks')}</div>
        </BreadcrumbHeader>
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
          availableFilterKeys={[
            'workflow_id',
            'objectAssignee',
            'objectParticipant',
            'objectMarking',
            'objectLabel',
            'createdBy',
            'creator_id',
          ]}
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
      </>
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
