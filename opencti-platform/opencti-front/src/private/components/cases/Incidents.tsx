import React, { FunctionComponent, useContext } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';
import {
  CasesFilter,
  IncidentsLinesCasesPaginationQuery,
  IncidentsLinesCasesPaginationQuery$variables,
} from './incidents/__generated__/IncidentsLinesCasesPaginationQuery.graphql';
import IncidentsLines, {
  incidentsLinesQuery,
} from './incidents/IncidentsLines';
import { IncidentLineDummy } from './incidents/IncidentLine';
import { UserContext } from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { IncidentLineCase_node$data } from './incidents/__generated__/IncidentLineCase_node.graphql';
import ToolBar from '../data/ToolBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import IncidentCreation from './incidents/IncidentCreation';
import ExportContextProvider from '../../../utils/ExportContextProvider';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

interface CasesProps {
  inputValue?: string;
}

export const LOCAL_STORAGE_KEY_CASE = 'view-cases-incidents';

const Incidents: FunctionComponent<CasesProps> = () => {
  const classes = useStyles();
  const { helper } = useContext(UserContext);
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<IncidentsLinesCasesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CASE,
    {
      searchTerm: '',
      sortBy: 'name',
      orderAsc: true,
      openExports: false,
      filters: {} as Filters,
    },
  );
  const key: ReadonlyArray<CasesFilter> = ['case_type'];
  const finalPaginationOptions = {
    ...paginationOptions,
    filters: [
      ...(paginationOptions.filters ?? []),
      { key, values: ['incident'] },
    ],
  };
  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<IncidentLineCase_node$data>(LOCAL_STORAGE_KEY_CASE);
  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const isRuntimeSort = helper?.isRuntimeFieldEnable();
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      priority: {
        label: 'Priority',
        width: '5%',
        isSortable: true,
      },
      severity: {
        label: 'Severity',
        width: '5%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '11%',
        isSortable: isRuntimeSort ?? false,
      },
      creator: {
        label: 'Creator',
        width: '11%',
        isSortable: isRuntimeSort ?? false,
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
        isSortable: isRuntimeSort ?? false,
      },
    };
    const queryRef = useQueryLoading<IncidentsLinesCasesPaginationQuery>(
      incidentsLinesQuery,
      finalPaginationOptions,
    );
    return (
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
        exportEntityType="Case"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={finalPaginationOptions}
        numberOfElements={numberOfElements}
        iconExtension={true}
        availableFilterKeys={[
          'x_opencti_workflow_id',
          'labelledBy',
          'createdBy',
          'creator',
          'markedBy',
          'confidence',
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
              paginationOptions={finalPaginationOptions}
              dataColumns={dataColumns}
              setNumberOfElements={helpers.handleSetNumberOfElements}
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              onToggleEntity={onToggleEntity}
              selectAll={selectAll}
            />
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              handleClearSelectedElements={handleClearSelectedElements}
              selectAll={selectAll}
              filters={{
                entity_type: [{ id: 'Case', value: 'Case' }],
                case_type: [{ id: 'incident', value: 'incident' }],
              }}
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <ExportContextProvider>
    <div className={classes.container}>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IncidentCreation paginationOptions={finalPaginationOptions} />
      </Security>
    </div>
    </ExportContextProvider>
  );
};

export default Incidents;
