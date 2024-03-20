import React, { FunctionComponent } from 'react';
import StixCyberObservableCreation from './stix_cyber_observables/StixCyberObservableCreation';
import { KnowledgeSecurity } from '../../../utils/Security';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import ListLines from '../../../components/list_lines/ListLines';
import StixCyberObservablesLines, { stixCyberObservablesLinesQuery, stixCyberObservablesLinesSearchQuery } from './stix_cyber_observables/StixCyberObservablesLines';
import ToolBar from '../data/ToolBar';
import { StixCyberObservablesLinesPaginationQuery$data } from './stix_cyber_observables/__generated__/StixCyberObservablesLinesPaginationQuery.graphql';
import { QueryRenderer } from '../../../relay/environment';
import useCopy from '../../../utils/hooks/useCopy';
import { StixCyberObservablesLinesSearchQuery$data } from './stix_cyber_observables/__generated__/StixCyberObservablesLinesSearchQuery.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { StixCyberObservableLine_node$data } from './stix_cyber_observables/__generated__/StixCyberObservableLine_node.graphql';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const LOCAL_STORAGE_KEY = 'stixCyberObservables';

const StixCyberObservables: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const { viewStorage, paginationOptions, helpers } = usePaginationLocalStorage(
    LOCAL_STORAGE_KEY,
    {
      filters: {
        ...emptyFilterGroup,
        filters: useGetDefaultFilterObject(['entity_type', 'sightedBy'], ['Stix-Cyber-Observable']),
      },
      searchTerm: '',
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

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Cyber-Observable', filters);

  const {
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<StixCyberObservableLine_node$data>(LOCAL_STORAGE_KEY);

  const getValuesForCopy = (
    data: StixCyberObservablesLinesSearchQuery$data,
  ) => {
    return (data.stixCyberObservables?.edges ?? []).map((o) => (o
      ? { id: o.node.id, value: o.node.observable_value }
      : { id: '', value: '' }));
  };

  const handleCopy = useCopy<StixCyberObservablesLinesSearchQuery$data>(
    {
      filters: contextFilters,
      searchTerm: searchTerm ?? '',
      query: stixCyberObservablesLinesSearchQuery,
      selectedValues: Object.values(selectedElements).map(
        ({ observable_value }) => observable_value,
      ),
      deselectedIds: Object.values(deSelectedElements).map((o) => o.id),
      getValuesForCopy,
    },
    selectAll,
  );

  const buildColumns = () => {
    return {
      entity_type: {
        label: 'Type',
        width: '12%',
        isSortable: true,
      },
      observable_value: {
        label: 'Representation',
        width: '25%',
        isSortable: isRuntimeSort,
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
  };

  const renderLines = () => {
    return (
      <>
        <ListLines
          helpers={helpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={buildColumns()}
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
          exportContext={{ entity_type: 'Stix-Cyber-Observable' }}
          availableEntityTypes={['Stix-Cyber-Observable']}
          keyword={searchTerm}
          filters={filters}
          iconExtension={true}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
        >
          <QueryRenderer
            query={stixCyberObservablesLinesQuery}
            variables={paginationOptions}
            render={({
              props,
            }: {
              props: StixCyberObservablesLinesPaginationQuery$data;
            }) => (
              <StixCyberObservablesLines
                data={props}
                paginationOptions={paginationOptions}
                dataColumns={buildColumns()}
                initialLoading={props === null}
                onLabelClick={helpers.handleAddFilter}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
                setNumberOfElements={helpers.handleSetNumberOfElements}
              />
            )}
          />
        </ListLines>
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          filters={contextFilters}
          search={searchTerm}
          handleClearSelectedElements={handleClearSelectedElements}
          handleCopy={handleCopy}
        />
      </>
    );
  };

  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Observations') }, { label: t_i18n('Observables'), current: true }]} />
      {renderLines()}
      <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Stix-Cyber-Observable'>
        <StixCyberObservableCreation
          paginationKey="Pagination_stixCyberObservables"
          paginationOptions={paginationOptions}
          contextual={false}
          open={false}
          handleClose={undefined}
          type={undefined}
          display={undefined}
          speeddial={false}
          inputValue={undefined}
        />
      </KnowledgeSecurity>
    </ExportContextProvider>
  );
};

export default StixCyberObservables;
