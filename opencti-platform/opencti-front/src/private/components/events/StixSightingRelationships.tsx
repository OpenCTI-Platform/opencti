import React from 'react';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import StixSightingRelationshipsLines, { stixSightingRelationshipsLinesQuery } from './stix_sighting_relationships/StixSightingRelationshipsLines';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import {
  StixSightingRelationshipsLinesPaginationQuery$data,
  StixSightingRelationshipsLinesPaginationQuery$variables,
} from './stix_sighting_relationships/__generated__/StixSightingRelationshipsLinesPaginationQuery.graphql';
import useEntityToggle from '../../../utils/hooks/useEntityToggle';
import { StixSightingRelationshipLine_node$data } from './stix_sighting_relationships/__generated__/StixSightingRelationshipLine_node.graphql';
import ToolBar from '../data/ToolBar';
import ExportContextProvider from '../../../utils/ExportContextProvider';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';

const dataColumns = {
  x_opencti_negative: {
    label: 'x_opencti_negative',
    width: '10%',
    isSortable: true,
  },
  attribute_count: {
    label: 'Nb.',
    width: 80,
    isSortable: true,
  },
  name: {
    label: 'Source entity',
    width: '15%',
    isSortable: false,
  },
  entity_type: {
    label: 'Source type',
    width: '12%',
    isSortable: false,
  },
  entity: {
    label: 'Target entity',
    width: '12%',
    isSortable: false,
  },
  first_seen: {
    label: 'First obs.',
    width: '12%',
    isSortable: true,
  },
  last_seen: {
    label: 'Last obs.',
    width: '12%',
    isSortable: true,
  },
  confidence: {
    width: '10%',
    label: 'Confidence',
    isSortable: true,
  },
  x_opencti_workflow_id: {
    label: 'Status',
    isSortable: true,
  },
};

const LOCAL_STORAGE_KEY = 'stixSightingRelationships';

const StixSightingRelationships = () => {
  const { t_i18n } = useFormatter();
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<StixSightingRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: {
        ...emptyFilterGroup,
        filters: useGetDefaultFilterObject(['toSightingId', 'x_opencti_negative'], ['stix-sighting-relationship']),
      },
      searchTerm: '',
      sortBy: 'last_seen',
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
    onToggleEntity,
    numberOfSelectedElements,
    handleClearSelectedElements,
    selectedElements,
    deSelectedElements,
    handleToggleSelectAll,
    selectAll,
  } = useEntityToggle<StixSightingRelationshipLine_node$data>(LOCAL_STORAGE_KEY);

  const contextFilters = useBuildEntityTypeBasedFilterContext('stix-sighting-relationship', filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters };

  const renderLines = () => {
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
          handleToggleSelectAll={handleToggleSelectAll}
          selectAll={selectAll}
          openExports={openExports}
          exportContext={{ entity_type: 'stix-sighting-relationship' }}
          keyword={searchTerm}
          filters={filters}
          paginationOptions={queryPaginationOptions}
          numberOfElements={numberOfElements}
          secondaryAction={true}
          iconExtension={true}
        >
          <QueryRenderer
            query={stixSightingRelationshipsLinesQuery}
            variables={queryPaginationOptions}
            render={({
              props,
            }: {
              props: StixSightingRelationshipsLinesPaginationQuery$data;
            }) => (
              <StixSightingRelationshipsLines
                data={props}
                paginationOptions={queryPaginationOptions}
                dataColumns={dataColumns}
                initialLoading={props === null}
                onLabelClick={storageHelpers.handleAddFilter}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
                selectedElements={selectedElements}
                deSelectedElements={deSelectedElements}
                onToggleEntity={onToggleEntity}
                selectAll={selectAll}
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
          type="stix-sighting-relationship"
        />
      </>
    );
  };

  return (
    <ExportContextProvider>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Events') }, { label: t_i18n('Sightings'), current: true }]} />
      {renderLines()}
    </ExportContextProvider>
  );
};

export default StixSightingRelationships;
