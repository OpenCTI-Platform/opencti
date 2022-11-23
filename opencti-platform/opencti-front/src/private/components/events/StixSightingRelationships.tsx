import React from 'react';
import * as R from 'ramda';
import { QueryRenderer } from '../../../relay/environment';
import ListLines from '../../../components/list_lines/ListLines';
import StixSightingRelationshipsLines, {
  stixSightingRelationshipsLinesQuery,
} from './stix_sighting_relationships/StixSightingRelationshipsLines';
import { convertFilters } from '../../../utils/ListParameters';
import useLocalStorage, { localStorageToPaginationOptions } from '../../../utils/hooks/useLocalStorage';
import { isUniqFilter } from '../common/lists/Filters';
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
  const [viewStorage, setViewStorage] = useLocalStorage(LOCAL_STORAGE_KEY, {
    numberOfElements: { number: 0, symbol: '' },
    filters: {} as Filters,
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
  });

  const {
    numberOfElements,
    filters,
    searchTerm,
    sortBy,
    orderAsc,
    openExports,
  } = viewStorage;

  const handleRemoveFilter = (key: string) => setViewStorage((c) => ({ ...c, filters: R.dissoc(key, c.filters) }));

  const handleSearch = (value: string) => setViewStorage((c) => ({ ...c, searchTerm: value }));

  const handleSort = (field: string, order: boolean) => setViewStorage((c) => ({
    ...c,
    sortBy: field,
    orderAsc: order,
  }));

  const handleAddFilter = (key: string, id: string, value: Record<string, unknown>, event: KeyboardEvent) => {
    if (event) {
      event.stopPropagation();
      event.preventDefault();
    }
    if ((filters[key]?.length ?? 0) > 0) {
      setViewStorage((c) => ({
        ...c,
        filters: {
          ...c.filters,
          [key]: isUniqFilter(key)
            ? [{ id, value }]
            : [
              ...(c.filters[key].filter((f) => f.id !== id) ?? []),
              {
                id,
                value,
              },
            ],
        },
      }));
    } else {
      setViewStorage((c) => ({ ...c, filters: R.assoc(key, [{ id, value }], c.filters) }));
    }
  };

  const renderLines = (paginationOptions: StixSightingRelationshipsLinesPaginationQuery$variables) => (
    <ListLines
      sortBy={sortBy}
      orderAsc={orderAsc}
      dataColumns={dataColumns}
      handleSort={handleSort}
      handleSearch={handleSearch}
      handleAddFilter={handleAddFilter}
      handleRemoveFilter={handleRemoveFilter}
      handleToggleExports={() => setViewStorage((c) => ({ ...c, openExports: !c.openExports }))}
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
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            data={props}
            paginationOptions={paginationOptions}
            dataColumns={dataColumns}
            initialLoading={props === null}
            onLabelClick={handleAddFilter}
            setNumberOfElements={(value: { number: number, symbol: string }) => setViewStorage((c) => ({
              ...c,
              numberOfElements: value,
            }))}
          />
        )}
      />
    </ListLines>
  );

  let toSightingId = null;
  let processedFilters = filters;
  if (filters?.toSightingId) {
    toSightingId = R.head(filters.toSightingId)?.id;
    processedFilters = R.dissoc('toSightingId', processedFilters);
  }
  const finalFilters = convertFilters(processedFilters) as unknown as Filters;
  const paginationOptions = localStorageToPaginationOptions<StixSightingRelationshipsLinesPaginationQuery$variables>({
    ...viewStorage,
    toId: toSightingId,
    filters: finalFilters,
    count: 25,
  });
  return (
    <div>{renderLines(paginationOptions)}</div>
  );
};

export default StixSightingRelationships;
