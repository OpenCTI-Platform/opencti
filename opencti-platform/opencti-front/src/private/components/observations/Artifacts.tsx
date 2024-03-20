import React, { FunctionComponent } from 'react';
import { ArtifactLine_node$data } from '@components/observations/artifacts/__generated__/ArtifactLine_node.graphql';
import { ArtifactsLinesPaginationQuery, ArtifactsLinesPaginationQuery$variables } from '@components/observations/artifacts/__generated__/ArtifactsLinesPaginationQuery.graphql';
import { ArtifactLineDummy } from '@components/observations/artifacts/ArtifactLine';
import ListLines from '../../../components/list_lines/ListLines';
import { KnowledgeSecurity } from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ArtifactsLines, { artifactsLinesQuery } from './artifacts/ArtifactsLines';
import ArtifactCreation from './artifacts/ArtifactCreation';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'artifacts';

const Artifacts: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage<ArtifactsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
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

  const contextFilters = useBuildEntityTypeBasedFilterContext('Artifact', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ArtifactsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ArtifactsLinesPaginationQuery>(
    artifactsLinesQuery,
    queryPaginationOptions,
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
      label: 'Platform creation date',
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
    return (
      <>
        <ListLines
          helpers={helpers}
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
          exportContext={{ entity_type: 'Artifact' }}
          keyword={searchTerm}
          filters={filters}
          iconExtension={true}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
        >
          {queryRef && (
          <React.Suspense
            fallback={
              <>
                {Array(20)
                  .fill(0)
                  .map((_, idx) => (
                    <ArtifactLineDummy key={idx} dataColumns={dataColumns} />
                  ))}
              </>
                      }
          >
            <ArtifactsLines
              queryRef={queryRef}
              paginationOptions={queryPaginationOptions}
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
              filters={contextFilters}
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
    <div data-testid="artifact-page">
      <ExportContextProvider>
        <Breadcrumbs variant="list" elements={[{ label: t_i18n('Observations') }, { label: t_i18n('Artifacts'), current: true }]} />
        <div>
          {renderLines()}
          <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Artifact'>
            <ArtifactCreation
              paginationOptions={queryPaginationOptions}
            />
          </KnowledgeSecurity>
        </div>
      </ExportContextProvider>
    </div>
  );
};

export default Artifacts;
