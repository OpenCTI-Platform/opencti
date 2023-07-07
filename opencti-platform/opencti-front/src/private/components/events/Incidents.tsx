import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import IncidentsLines, {
  incidentsLinesPaginationQuery,
} from './incidents/IncidentsLines';
import IncidentCreation from './incidents/IncidentCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import { IncidentLineDummy } from './incidents/IncidentLine';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { IncidentLine_node$data } from './incidents/__generated__/IncidentLine_node.graphql';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import {
  IncidentsLinesPaginationQuery,
  IncidentsLinesPaginationQuery$variables,
} from './incidents/__generated__/IncidentsLinesPaginationQuery.graphql';

export const LOCAL_STORAGE_KEY = 'view-incidents';

const Incidents: FunctionComponent = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IncidentsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created',
      orderAsc: false,
      openExports: false,
      filters: {} as Filters,
    },
  );
  const {
    sortBy,
    orderAsc,
    searchTerm,
    filters,
    openExports,
    numberOfElements,
  } = viewStorage;
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<IncidentLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<IncidentsLinesPaginationQuery>(
    incidentsLinesPaginationQuery,
    paginationOptions,
  );
  // eslint-disable-next-line class-methods-use-this
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    name: {
      label: 'Name',
      width: '20%',
      isSortable: true,
    },
    incident_type: {
      label: 'Incident type',
      width: '8%',
      isSortable: true,
    },
    severity: {
      label: 'Severity',
      width: '5%',
      isSortable: true,
    },
    objectAssignee: {
      label: 'Assignees',
      width: '14%',
      isSortable: isRuntimeSort,
    },
    creator: {
      label: 'Creators',
      width: '11%',
      isSortable: isRuntimeSort,
    },
    objectLabel: {
      label: 'Labels',
      width: '15%',
      isSortable: false,
    },
    created: {
      label: 'Date',
      width: '10%',
      isSortable: true,
    },
    x_opencti_workflow_id: {
      label: 'Status',
      width: '8%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      width: '8%',
      isSortable: isRuntimeSort,
    },
  };
  const renderLines = () => {
    let renderFilters = filters;
    renderFilters = {
      ...renderFilters,
      entity_type: [{ id: 'Incident', value: 'Incident' }],
    };
    return (
      <>
        <ListLines
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={helpers.handleSort}
          handleSearch={helpers.handleSearch}
          handleAddFilter={helpers.handleAddFilter}
          handleRemoveFilter={helpers.handleRemoveFilter}
          handleToggleExports={helpers.handleToggleExports}
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          openExports={openExports}
          exportEntityType="Incident"
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'incident_type',
            'participant',
            'severity',
            'labelledBy',
            'markedBy',
            'confidence',
            'source',
            'createdBy',
            'creator',
            'created_start_date',
            'created_end_date',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((idx) => (
                      <IncidentLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <IncidentsLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                onLabelClick={helpers.handleAddFilter}
                setNumberOfElements={helpers.handleSetNumberOfElements}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
              />
            </React.Suspense>
          )}
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={renderFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Incident"
        />
      </>
    );
  };
  return (
    <ExportContextProvider>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IncidentCreation paginationOptions={paginationOptions} />
      </Security>
    </ExportContextProvider>
  );
};

export default Incidents;
