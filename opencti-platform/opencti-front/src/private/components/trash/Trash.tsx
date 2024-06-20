import React from 'react';
import DeleteOperationsLines, { deleteOperationsLinesQuery } from '@components/trash/all/DeleteOperationsLines';
import { DeleteOperationLineDummy } from '@components/trash/all/DeleteOperationLine';
import ToolBar from '@components/data/ToolBar';
import { DeleteOperationLine_node$data } from './all/__generated__/DeleteOperationLine_node.graphql';
import ListLines from '../../../components/list_lines/ListLines';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import type { DeleteOperationsLinesPaginationQuery, DeleteOperationsLinesPaginationQuery$variables } from './all/__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import { DataColumns } from '../../../components/list_lines';
import useAuth from '../../../utils/hooks/useAuth';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';

const LOCAL_STORAGE_KEY = 'trash';

const Trash: React.FC = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Trash'));
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DeleteOperationsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      filters: emptyFilterGroup,
    },
  );
  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;

  const {
    numberOfSelectedElements,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
    selectedElements,
    deSelectedElements,
    selectAll,
  } = useEntityToggle<DeleteOperationLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('DeleteOperation', filters);

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const queryRef = useQueryLoading<DeleteOperationsLinesPaginationQuery>(
    deleteOperationsLinesQuery,
    paginationOptions,
  );

  const renderLines = () => {
    const isRuntimeSort = isRuntimeFieldEnable() ?? false;
    const dataColumns: DataColumns = {
      main_entity_type: {
        label: 'Type',
        width: '12.5%',
        isSortable: false,
      },
      main_entity_name: {
        label: 'Representation',
        width: '37.5%',
        isSortable: true,
      },
      deletedBy: {
        label: 'Deleted by',
        width: '21%',
        isSortable: isRuntimeSort,
      },
      created_at: {
        label: 'Deletion date',
        width: '21%',
        isSortable: true,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
        width: '8%',
      },
    };
    return (
      <div data-testid="trash-page">
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
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          keyword={searchTerm}
          filters={filters}
          noPadding={true}
          iconExtension={true}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          secondaryAction={true}
          entityTypes={['DeleteOperation']}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <DeleteOperationLineDummy
                        key={idx}
                        dataColumns={dataColumns}
                      />
                    ))}
                </>
              }
            >
              <DeleteOperationsLines
                queryRef={queryRef}
                paginationOptions={paginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
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
          filters={contextFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="DeleteOperation"
          deleteDisable={true}
          deleteOperationEnabled={true}
          mergeDisable={true}
        />
      </div>
    );
  };
  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Trash'), current: true }]} />
      {renderLines()}
    </ExportContextProvider>
  );
};

export default Trash;
