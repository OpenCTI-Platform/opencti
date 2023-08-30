import React, { FunctionComponent } from 'react';
import { ArtifactLine_node$data } from '@components/observations/artifacts/__generated__/ArtifactLine_node.graphql';
import {
  ArtifactsLinesPaginationQuery,
  ArtifactsLinesPaginationQuery$variables,
} from '@components/observations/artifacts/__generated__/ArtifactsLinesPaginationQuery.graphql';
import { ArtifactLineDummy } from '@components/observations/artifacts/ArtifactLine';
import ListLines from '../../../components/list_lines/ListLines';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ArtifactsLines, { artifactsLinesQuery } from './artifacts/ArtifactsLines';
import ArtifactCreation from './artifacts/ArtifactCreation';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { filtersWithEntityType, initialFilterGroup } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'view-artifacts';

const Artifacts: FunctionComponent = () => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<ArtifactsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: initialFilterGroup,
      searchTerm: '',
      sortBy: 'created_at',
      orderAsc: false,
      openExports: false,
      types: ['Artifact'],
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
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<ArtifactLine_node$data>(LOCAL_STORAGE_KEY);
  const queryRef = useQueryLoading<ArtifactsLinesPaginationQuery>(
    artifactsLinesQuery,
    paginationOptions,
  );

  const dataColumns = {
    observable_value: {
      label: 'Value',
      width: '12%',
      isSortable: isRuntimeSort,
    },
    file_name: {
      label: 'File name',
      width: '12%',
      isSortable: false,
    },
    file_mime_type: {
      label: 'Mime/Type',
      width: '8%',
      isSortable: false,
    },
    file_size: {
      label: 'File size',
      width: '8%',
      isSortable: false,
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
      label: 'Date',
      width: '10%',
      isSortable: true,
    },
    objectMarking: {
      label: 'Marking',
      width: '10%',
      isSortable: isRuntimeSort,
    },
  };

  const renderLines = () => {
    const toolBarFilters = filtersWithEntityType(filters, 'Artifact');

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
              handleSwitchGlobalMode={helpers.handleSwitchGlobalMode}
              handleSwitchLocalMode={helpers.handleSwitchLocalMode}
              handleToggleExports={helpers.handleToggleExports}
              openExports={openExports}
              handleToggleSelectAll={handleToggleSelectAll}
              selectAll={selectAll}
              exportEntityType="Artifact"
              exportContext={null}
              keyword={searchTerm}
              filters={filters}
              iconExtension={true}
              paginationOptions={paginationOptions}
              numberOfElements={numberOfElements}
              availableFilterKeys={[
                'objectLabel',
                'objectMarking',
                'created_at',
                'createdBy',
              ]}
            >
              {queryRef && (
                  <React.Suspense
                      fallback={
                        <>
                          {Array(20)
                            .fill(0)
                            .map((idx) => (
                                  <ArtifactLineDummy key={idx} dataColumns={dataColumns} />
                            ))}
                        </>
                      }
                  >
                  <ArtifactsLines
                    queryRef={queryRef}
                    paginationOptions={paginationOptions}
                    dataColumns={dataColumns}
                    onLabelClick={helpers.handleAddFilter}
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    onToggleEntity={onToggleEntity}
                    selectAll={selectAll}
                    setNumberOfElements={helpers.handleSetNumberOfElements}
                  />
                  <ToolBar
                    selectedElements={selectedElements}
                    deSelectedElements={deSelectedElements}
                    numberOfSelectedElements={numberOfSelectedElements}
                    selectAll={selectAll}
                    filters={toolBarFilters}
                    search={searchTerm}
                    handleClearSelectedElements={handleClearSelectedElements}
                  />
                  </React.Suspense>
              )}
            </ListLines>
          </>
    );
  };

  return (
      <ExportContextProvider>
        <div>
          {renderLines()}
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ArtifactCreation
              paginationOptions={paginationOptions}
            />
          </Security>
        </div>
      </ExportContextProvider>
  );
};

export default Artifacts;
