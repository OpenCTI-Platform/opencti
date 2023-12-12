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
import { filtersWithEntityType, findFilterFromKey, GqlFilterGroup, emptyFilterGroup } from '../../../utils/filters/filtersUtils';

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
    label: 'Name',
    width: '15%',
    isSortable: false,
  },
  entity_type: {
    label: 'Entity type',
    width: '12%',
    isSortable: false,
  },
  entity: {
    label: 'Entity',
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
  const {
    viewStorage,
    paginationOptions: rawPaginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<StixSightingRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    {
      filters: emptyFilterGroup,
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

  const renderLines = (
    paginationOptions: StixSightingRelationshipsLinesPaginationQuery$variables,
  ) => {
    const toolBarFilters = filtersWithEntityType(filters, 'stix-sighting-relationship');
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
          exportEntityType="stix-sighting-relationship"
          keyword={searchTerm}
          filters={filters}
          paginationOptions={paginationOptions}
          numberOfElements={numberOfElements}
          secondaryAction={true}
          iconExtension={true}
          availableFilterKeys={[
            'x_opencti_workflow_id',
            'objectLabel',
            'objectMarking',
            'createdBy',
            'confidence',
            'created',
            'toSightingId',
            'x_opencti_negative',
            'creator',
          ]}
        >
          <QueryRenderer
            query={stixSightingRelationshipsLinesQuery}
            variables={rawPaginationOptions}
            render={({
              props,
            }: {
              props: StixSightingRelationshipsLinesPaginationQuery$data;
            }) => (
              <StixSightingRelationshipsLines
                data={props}
                paginationOptions={paginationOptions}
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
          filters={toolBarFilters}
          handleClearSelectedElements={handleClearSelectedElements}
          type="stix-sighting-relationship"
        />
      </>
    );
  };

  // As toSightingId must be converted to a connection nested filter in backend
  // we need to remove it from the filters and use a specific api parameter instead
  let toSightingId: string | undefined;
  let newFilters = filters;
  const toSightingIdFilter = newFilters?.filters ? findFilterFromKey(newFilters.filters, 'toSightingId') : undefined;
  if (newFilters && toSightingIdFilter) {
    toSightingId = String(toSightingIdFilter.values?.[0]);
    newFilters = {
      ...newFilters,
      filters: newFilters.filters.filter((f) => f.key !== 'toSightingId'),
    };
  }
  const enrichedPaginationOptions: StixSightingRelationshipsLinesPaginationQuery$variables = {
    ...rawPaginationOptions,
    toId: toSightingId,
    filters: newFilters as unknown as GqlFilterGroup,
  };
  return (
    <ExportContextProvider>
      {renderLines(enrichedPaginationOptions)}
    </ExportContextProvider>
  );
};

export default StixSightingRelationships;
