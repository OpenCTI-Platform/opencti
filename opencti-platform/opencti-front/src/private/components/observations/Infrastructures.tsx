import React from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import ListLines from '../../../components/list_lines/ListLines';
import InfrastructuresLines, {
  infrastructuresLinesQuery,
} from './infrastructures/InfrastructuresLines';
import InfrastructureCreation from './infrastructures/InfrastructureCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import {
  InfrastructuresLinesPaginationQuery,
  InfrastructuresLinesPaginationQuery$variables,
} from './infrastructures/__generated__/InfrastructuresLinesPaginationQuery.graphql';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { InfrastructureLineDummy } from './infrastructures/InfrastructureLine';
import ToolBar from '../data/ToolBar';
import { InfrastructureLine_node$data } from './infrastructures/__generated__/InfrastructureLine_node.graphql';

export const LOCAL_STORAGE_KEY_INFRASTRUCTURES = 'view-infrastructures';

const Infrastructures = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<InfrastructuresLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_INFRASTRUCTURES,
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
  } = useEntityToggle<InfrastructureLine_node$data>(
    LOCAL_STORAGE_KEY_INFRASTRUCTURES,
  );
  const renderLines = () => {
    const {
      sortBy,
      orderAsc,
      searchTerm,
      filters,
      openExports,
      numberOfElements,
    } = viewStorage;
    let finalFilters = filters;
    finalFilters = {
      ...finalFilters,
      entity_type: [{ id: 'Infrastructure', value: 'Infrastructure' }],
    };
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: true,
      },
      infrastructure_types: {
        label: 'Type',
        width: '8%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '12%',
        isSortable: isRuntimeSort,
      },
      creator: {
        label: 'Creators',
        width: '12%',
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
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    const queryRef = useQueryLoading<InfrastructuresLinesPaginationQuery>(
      infrastructuresLinesQuery,
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
        exportEntityType="Infrastructure"
        keyword={searchTerm}
        filters={filters}
        paginationOptions={paginationOptions}
        numberOfElements={numberOfElements}
        iconExtension={true}
        availableFilterKeys={[
          'labelledBy',
          'markedBy',
          'created_start_date',
          'created_end_date',
          'createdBy',
          'confidence',
        ]}
      >
        {queryRef && (
          <React.Suspense
            fallback={
              <>
              {Array(20)
                .fill(0)
                .map((idx) => (
                  <InfrastructureLineDummy
                    key={idx}
                    dataColumns={dataColumns}
                  />
                ))}
              </>
            }
          >
            <InfrastructuresLines
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
            <ToolBar
              selectedElements={selectedElements}
              deSelectedElements={deSelectedElements}
              numberOfSelectedElements={numberOfSelectedElements}
              handleClearSelectedElements={handleClearSelectedElements}
              selectAll={selectAll}
              search={searchTerm}
              filters={finalFilters}
              type="Infrastructure"
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
        <InfrastructureCreation paginationOptions={paginationOptions} />
      </Security>
    </ExportContextProvider>
  );
};

export default Infrastructures;
