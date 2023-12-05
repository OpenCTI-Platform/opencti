import React from 'react';
import {
  EntitiesStixDomainObjectsLinesPaginationQuery,
  EntitiesStixDomainObjectsLinesPaginationQuery$variables,
} from '@components/data/entities/__generated__/EntitiesStixDomainObjectsLinesPaginationQuery.graphql';
import { EntitiesStixDomainObjectLineDummy } from '@components/data/entities/EntitiesStixDomainObjectLine';
import { EntitiesStixDomainObjectLine_node$data } from '@components/data/entities/__generated__/EntitiesStixDomainObjectLine_node.graphql';
import ListLines from '../../../components/list_lines/ListLines';
import ToolBar from './ToolBar';
import EntitiesStixDomainObjectsLines, {
  entitiesStixDomainObjectsLinesQuery,
} from './entities/EntitiesStixDomainObjectsLines';
import useAuth from '../../../utils/hooks/useAuth';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'entities';

const Entities = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<EntitiesStixDomainObjectsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    numberOfSelectedElements,
  } = useEntityToggle<EntitiesStixDomainObjectLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<EntitiesStixDomainObjectsLinesPaginationQuery>(
    entitiesStixDomainObjectsLinesQuery,
    paginationOptions,
  );
  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns = {
      entity_type: {
        label: 'Type',
        width: '12%',
        isSortable: true,
      },
      name: {
        label: 'Name',
        width: '25%',
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
      created_at: {
        label: 'Creation date',
        width: '15%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
      <>
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          handleAddFilter={storageHelpers.handleAddFilter}
          handleRemoveFilter={storageHelpers.handleRemoveFilter}
          handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
          handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
          handleToggleExports={storageHelpers.handleToggleExports}
          openExports={openExports}
          handleToggleSelectAll={handleToggleSelectAll}
          availableEntityTypes={['Stix-Domain-Object']}
          exportEntityType="Stix-Domain-Object"
          selectAll={selectAll}
          disableCards={true}
          keyword={searchTerm}
          filters={filters}
          noPadding={true}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          availableFilterKeys={[
            'entity_type',
            'objectLabel',
            'objectMarking',
            'createdBy',
            'source_reliability',
            'confidence',
            'creator_id',
            'created',
            'created_at',
          ]}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <EntitiesStixDomainObjectLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
              }
            >
              <EntitiesStixDomainObjectsLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
              <ToolBar
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                numberOfSelectedElements={numberOfSelectedElements}
                selectAll={selectAll}
                search={searchTerm}
                filters={filters}
                handleClearSelectedElements={handleClearSelectedElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </>
    );
  };
  return <ExportContextProvider>{renderLines()}</ExportContextProvider>;
};

export default Entities;
