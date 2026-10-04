import React from 'react';
import { graphql } from 'react-relay';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../../components/i18n';
import DataTable from '../../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import ProvenanceSourcesAction from './ProvenanceSourcesAction';
import {
  ProvenanceKnowledgeEntitiesLinesPaginationQuery,
  ProvenanceKnowledgeEntitiesLinesPaginationQuery$variables,
} from './__generated__/ProvenanceKnowledgeEntitiesLinesPaginationQuery.graphql';
import { ProvenanceKnowledgeEntitiesLines_data$data } from './__generated__/ProvenanceKnowledgeEntitiesLines_data.graphql';

const provenanceKnowledgeEntitiesLineFragment = graphql`
  fragment ProvenanceKnowledgeEntitiesLine_node on StixCoreObject {
    id
    entity_type
    created_at
    representative {
      main
    }
    corroboration_count
    freshness_days
    freshness_stale
    freshness_stale_at
    last_asserted_at
    has_conflicts
    x_opencti_conflicts {
      field
      field_label
    }
    draftVersion {
      draft_id
      draft_operation
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
  }
`;

const provenanceKnowledgeEntitiesLinesQuery = graphql`
  query ProvenanceKnowledgeEntitiesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ProvenanceKnowledgeEntitiesLines_data
    @arguments(search: $search, count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
  }
`;

const provenanceKnowledgeEntitiesLinesFragment = graphql`
  fragment ProvenanceKnowledgeEntitiesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreObjectsOrdering", defaultValue: last_asserted_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ProvenanceKnowledgeEntitiesLinesRefetchQuery") {
    stixCoreObjects(search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
    @connection(key: "Pagination_provenance_stixCoreObjects") {
      edges {
        node {
          id
          ...ProvenanceKnowledgeEntitiesLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

export const conflictingFieldsColumn: DataTableProps['dataColumns'][string] = {
  id: 'conflict_fields',
  label: 'Conflicting fields',
  percentWidth: 16,
  isSortable: false,
  render: ({ x_opencti_conflicts }: { x_opencti_conflicts?: ReadonlyArray<{ field: string; field_label?: string | null }> | null }, { t_i18n }) => {
    const fields = (x_opencti_conflicts ?? []).map((conflict) => t_i18n(conflict.field_label ?? conflict.field));
    return fields.length > 0 ? fields.join(', ') : '-';
  },
};

interface ProvenanceKnowledgeEntitiesProps {
  storageKey: string;
  // Fixed provenance filter of the view (stale knowledge, conflicts), not editable by the user
  fixedFilters: FilterGroup;
  withConflicts?: boolean;
  // Shown when nothing matches the fixed filter (no conflict, no stale knowledge)
  emptyMessage: string;
}

const ProvenanceKnowledgeEntities = ({ storageKey, fixedFilters, withConflicts = false, emptyMessage }: ProvenanceKnowledgeEntitiesProps) => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'last_asserted_at',
    orderAsc: true,
    openExports: false,
  };
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<ProvenanceKnowledgeEntitiesLinesPaginationQuery$variables>(
    storageKey,
    initialValues,
  );
  const hasUserFilters = isFilterGroupNotEmpty(viewStorage.filters) || !!viewStorage.searchTerm;
  const userFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', viewStorage.filters);
  const contextFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [fixedFilters, userFilters as FilterGroup] };
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as ProvenanceKnowledgeEntitiesLinesPaginationQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<ProvenanceKnowledgeEntitiesLinesPaginationQuery>(provenanceKnowledgeEntitiesLinesQuery, queryPaginationOptions);
  const refresh = () => loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });

  const dataColumns: DataTableProps['dataColumns'] = {
    entity_type: { percentWidth: 11 },
    name: { percentWidth: withConflicts ? 18 : 31 },
    ...(withConflicts ? { conflict_fields: { ...conflictingFieldsColumn, percentWidth: 13 } } : {}),
    corroboration_count: { percentWidth: 11 },
    freshness_days: { percentWidth: 9 },
    last_asserted_at: { percentWidth: 11 },
    createdBy: { percentWidth: 11, isSortable: false },
    objectMarking: { percentWidth: 9, isSortable: false },
  };

  const preloadedPaginationProps = {
    linesQuery: provenanceKnowledgeEntitiesLinesQuery,
    linesFragment: provenanceKnowledgeEntitiesLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ProvenanceKnowledgeEntitiesLinesPaginationQuery>;

  return queryRef ? (
    <DataTable
      dataColumns={dataColumns}
      resolvePath={(data: ProvenanceKnowledgeEntitiesLines_data$data) => data.stixCoreObjects?.edges?.map((edge) => edge?.node)}
      storageKey={storageKey}
      initialValues={initialValues}
      contextFilters={contextFilters}
      lineFragment={provenanceKnowledgeEntitiesLineFragment}
      preloadedPaginationProps={preloadedPaginationProps}
      emptyStateMessage={hasUserFilters ? t_i18n('No result for these filters') : emptyMessage}
      exportContext={{ entity_type: 'Stix-Core-Object' }}
      availableEntityTypes={['Stix-Core-Object']}
      actions={(row: { id: string }) => <ProvenanceSourcesAction id={row.id} onChange={refresh} />}
    />
  ) : null;
};

export default ProvenanceKnowledgeEntities;
