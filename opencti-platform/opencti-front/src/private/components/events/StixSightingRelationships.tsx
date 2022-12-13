import React from 'react';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import StixSightingRelationshipsLines, {
  stixSightingRelationshipsLinesQuery,
} from './stix_sighting_relationships/StixSightingRelationshipsLines';
import useLocalStorage, { localStorageToPaginationOptions } from '../../../utils/hooks/useLocalStorage';
import { Filters } from '../../../components/list_lines';
import {
  StixSightingRelationshipsLinesPaginationQuery$variables,
} from './stix_sighting_relationships/__generated__/StixSightingRelationshipsLinesPaginationQuery.graphql';

const dataColumns = {
  x_opencti_negative: {
    label: 'filter_x_opencti_negative',
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

const LOCAL_STORAGE_KEY = 'view-stix-sighting-relationships';

const StixSightingRelationships = () => {
  const [viewStorage, _, storageHelpers] = useLocalStorage(LOCAL_STORAGE_KEY, {
    numberOfElements: { number: 0, symbol: '' },
    filters: {} as Filters,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    count: 25,
  });

  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;

  const renderLines = (paginationOptions: StixSightingRelationshipsLinesPaginationQuery$variables) => (
    <ListLines
      sortBy={sortBy}
      orderAsc={orderAsc}
      dataColumns={dataColumns}
      handleSort={storageHelpers.handleSort}
      handleSearch={storageHelpers.handleSearch}
      handleAddFilter={storageHelpers.handleAddFilter}
      handleRemoveFilter={storageHelpers.handleRemoveFilter}
      handleToggleExports={storageHelpers.handleToggleExports}
      openExports={openExports}
      exportEntityType="stix-sighting-relationship"
      keyword={searchTerm}
      filters={filters}
      paginationOptions={paginationOptions}
      numberOfElements={numberOfElements}
      secondaryAction={true}
      availableFilterKeys={[
        'labelledBy',
        'markedBy',
        'x_opencti_workflow_id',
        'created_start_date',
        'created_end_date',
        'createdBy',
        'toSightingId',
        'x_opencti_negative',
      ]}
    >
      <QueryRenderer
        query={stixSightingRelationshipsLinesQuery}
        variables={paginationOptions}
        render={({ props }: { props: unknown }) => (
          <StixSightingRelationshipsLines
            data={props}
            paginationOptions={paginationOptions}
            dataColumns={dataColumns}
            initialLoading={props === null}
            onLabelClick={storageHelpers.handleAddFilter}
            setNumberOfElements={storageHelpers.handleSetNumberOfElements}
          />
        )}
      />
    </ListLines>
  );

  let toSightingId = null;
  let processedFilters = filters as Filters;
  if (filters?.toSightingId) {
    toSightingId = R.head(filters.toSightingId)?.id;
    processedFilters = R.dissoc<Filters, string>('toSightingId', processedFilters);
  }
  const paginationOptions = localStorageToPaginationOptions<StixSightingRelationshipsLinesPaginationQuery$variables>({
    ...viewStorage,
    toId: toSightingId,
    filters: processedFilters,
    count: viewStorage.count ?? 25,
  });
  return (
    <div>{renderLines(paginationOptions)}</div>
  );
};

export default StixSightingRelationships;
