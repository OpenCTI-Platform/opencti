import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import ObservedDatasLines, { observedDatasLinesQuery } from './observed_data/ObservedDatasLines';
import ObservedDataCreation from './observed_data/ObservedDataCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { ObservedDataLine_node$data } from './observed_data/__generated__/ObservedDataLine_node.graphql';
import { ObservedDatasLinesPaginationQuery$data, ObservedDatasLinesPaginationQuery$variables } from './observed_data/__generated__/ObservedDatasLinesPaginationQuery.graphql';
import { ModuleHelper } from '../../../utils/platformModulesHelper';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'observedDatas';

const ObservedDatas: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const {
    viewStorage,
    helpers: storageHelpers,
    paginationOptions,
  } = usePaginationLocalStorage<ObservedDatasLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      searchTerm: '',
      sortBy: 'last_observed',
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
  } = useEntityToggle<ObservedDataLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Observed-Data', filters);
  const queryPaginationOptions = {
    ...paginationOptions, filters: contextFilters,
  } as unknown as ObservedDatasLinesPaginationQuery$variables;

  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const renderLines = (helper: ModuleHelper | undefined) => {
    const isRuntimeSort = helper?.isRuntimeFieldEnable();
    const dataColumns = {
      name: {
        label: 'Name',
        width: '25%',
        isSortable: false,
      },
      number_observed: {
        label: 'Nb.',
        width: 80,
        isSortable: true,
      },
      first_observed: {
        label: 'First obs.',
        width: '12%',
        isSortable: true,
      },
      last_observed: {
        label: 'Last obs.',
        width: '12%',
        isSortable: true,
      },
      createdBy: {
        label: 'Author',
        width: '15%',
        isSortable: isRuntimeSort,
      },
      objectLabel: {
        label: 'Labels',
        width: '15%',
        isSortable: false,
      },
      objectMarking: {
        label: 'Marking',
        isSortable: isRuntimeSort,
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
          selectAll={selectAll}
          exportContext={{ entity_type: 'Observed-Data' }}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          iconExtension={true}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ObservedDataCreation paginationOptions={queryPaginationOptions}/>
            </Security>
          )}
        >
          <QueryRenderer
            query={observedDatasLinesQuery}
            variables={queryPaginationOptions}
            render={({
              props,
            }: {
              props: ObservedDatasLinesPaginationQuery$data;
            }) => (
              <ObservedDatasLines
                data={props}
                paginationOptions={queryPaginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                onLabelClick={storageHelpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            )}
          />
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          search={searchTerm}
          filters={contextFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="Observed-Data"
        />
      </>
    );
  };

  return (
    <UserContext.Consumer>
      {({ platformModuleHelpers }) => (
        <ExportContextProvider>
          <Breadcrumbs variant="list" elements={[{ label: t_i18n('Events') }, { label: t_i18n('Observed datas'), current: true }]} />
          {renderLines(platformModuleHelpers)}
          {!isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <ObservedDataCreation paginationOptions={queryPaginationOptions}/>
            </Security>
          )}
        </ExportContextProvider>
      )}
    </UserContext.Consumer>
  );
};

export default ObservedDatas;
