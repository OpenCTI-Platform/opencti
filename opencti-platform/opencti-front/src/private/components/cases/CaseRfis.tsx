import React, { FunctionComponent } from 'react';
import ListLines from '../../../components/list_lines/ListLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { Filters } from '../../../components/list_lines';
import useAuth from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import ToolBar from '../data/ToolBar';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import CaseRfiCreation from './case_rfis/CaseRfiCreation';
import CaseRfisLines, { caseRfisLinesQuery } from './case_rfis/CaseRfiLines';
import { CaseRfiLineDummy } from './case_rfis/CaseRfiLine';
import {
  CaseRfiLinesCasesPaginationQuery,
  CaseRfiLinesCasesPaginationQuery$variables,
} from './case_rfis/__generated__/CaseRfiLinesCasesPaginationQuery.graphql';
import { CaseRfiLineCase_node$data } from './case_rfis/__generated__/CaseRfiLineCase_node.graphql';

interface CaseRfisProps {
  inputValue?: string;
}

export const LOCAL_STORAGE_KEY_CASE_RFI = 'view-caseRfis';

const CaseRfis: FunctionComponent<CaseRfisProps> = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<CaseRfiLinesCasesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_RFI,
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
  } = useEntityToggle<CaseRfiLineCase_node$data>(LOCAL_STORAGE_KEY_CASE_RFI);
  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '22%',
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
    const queryRef = useQueryLoading<CaseRfiLinesCasesPaginationQuery>(
      caseRfisLinesQuery,
      paginationOptions,
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
        exportEntityType="Case-Rfi"
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
          'severity',
          'priority',
          'labelledBy',
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
                    <CaseRfiLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
            }
          >
            <CaseRfisLines
              queryRef={queryRef}
              paginationOptions={paginationOptions}
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
                entity_type: [{ id: 'Case-Rfi', value: 'Case-Rfi' }],
              }}
              type="Case-Rfi"
            />
          </React.Suspense>
        )}
      </ListLines>
    );
  };
  return (
    <ExportContextProvider>
      {renderLines()}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CaseRfiCreation paginationOptions={paginationOptions} />
      </Security>
    </ExportContextProvider>
  );
};

export default CaseRfis;
