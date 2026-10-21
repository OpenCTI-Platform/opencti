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
import { conflictingFieldsColumn } from './ProvenanceKnowledgeEntities';
import {
  ProvenanceKnowledgeSightingsLinesPaginationQuery,
  ProvenanceKnowledgeSightingsLinesPaginationQuery$variables,
} from './__generated__/ProvenanceKnowledgeSightingsLinesPaginationQuery.graphql';
import { ProvenanceKnowledgeSightingsLines_data$data } from './__generated__/ProvenanceKnowledgeSightingsLines_data.graphql';

const provenanceKnowledgeSightingsLineFragment = graphql`
  fragment ProvenanceKnowledgeSightingsLine_node on StixSightingRelationship {
    id
    entity_type
    parent_types
    created_at
    attribute_count
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
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    from {
      ... on BasicObject {
        id
        entity_type
        parent_types
      }
      ... on BasicRelationship {
        id
        entity_type
        parent_types
      }
      ... on StixCoreObject {
        representative {
          main
        }
      }
      ... on StixCoreRelationship {
        representative {
          main
        }
      }
    }
    to {
      ... on BasicObject {
        id
        entity_type
        parent_types
      }
      ... on BasicRelationship {
        id
        entity_type
        parent_types
      }
      ... on StixCoreObject {
        representative {
          main
        }
      }
      ... on StixCoreRelationship {
        representative {
          main
        }
      }
    }
  }
`;

const provenanceKnowledgeSightingsLinesQuery = graphql`
  query ProvenanceKnowledgeSightingsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixSightingRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ProvenanceKnowledgeSightingsLines_data
    @arguments(search: $search, count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
  }
`;

const provenanceKnowledgeSightingsLinesFragment = graphql`
  fragment ProvenanceKnowledgeSightingsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixSightingRelationshipsOrdering", defaultValue: last_asserted_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ProvenanceKnowledgeSightingsLinesRefetchQuery") {
    stixSightingRelationships(search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
    @connection(key: "Pagination_provenance_stixSightingRelationships") {
      edges {
        node {
          id
          ...ProvenanceKnowledgeSightingsLine_node
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

interface ProvenanceKnowledgeSightingsProps {
  storageKey: string;
  // Fixed provenance filter of the view (stale knowledge, conflicts), not editable by the user
  fixedFilters: FilterGroup;
  withConflicts?: boolean;
  // Shown when nothing matches the fixed filter (no conflict, no stale knowledge)
  emptyMessage: string;
}

const ProvenanceKnowledgeSightings = ({ storageKey, fixedFilters, withConflicts = false, emptyMessage }: ProvenanceKnowledgeSightingsProps) => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'last_asserted_at',
    orderAsc: true,
    openExports: false,
  };
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<ProvenanceKnowledgeSightingsLinesPaginationQuery$variables>(
    storageKey,
    initialValues,
  );
  const hasUserFilters = isFilterGroupNotEmpty(viewStorage.filters) || !!viewStorage.searchTerm;
  const userFilters = useBuildEntityTypeBasedFilterContext('stix-sighting-relationship', viewStorage.filters);
  const contextFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [fixedFilters, userFilters as FilterGroup] };
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as ProvenanceKnowledgeSightingsLinesPaginationQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<ProvenanceKnowledgeSightingsLinesPaginationQuery>(
    provenanceKnowledgeSightingsLinesQuery,
    queryPaginationOptions,
  );
  const refresh = () => loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });

  const dataColumns: DataTableProps['dataColumns'] = {
    fromType: { percentWidth: 8 },
    fromName: { percentWidth: withConflicts ? 13 : 18 },
    toType: { percentWidth: 8 },
    toName: { percentWidth: withConflicts ? 13 : 18 },
    ...(withConflicts ? { conflict_fields: { ...conflictingFieldsColumn, percentWidth: 12 } } : {}),
    attribute_count: { percentWidth: 7 },
    corroboration_count: { percentWidth: 11 },
    freshness_days: { percentWidth: 9 },
    last_asserted_at: { percentWidth: withConflicts ? 10 : 11 },
    objectMarking: { percentWidth: withConflicts ? 9 : 10, isSortable: false },
  };

  const preloadedPaginationProps = {
    linesQuery: provenanceKnowledgeSightingsLinesQuery,
    linesFragment: provenanceKnowledgeSightingsLinesFragment,
    queryRef,
    nodePath: ['stixSightingRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ProvenanceKnowledgeSightingsLinesPaginationQuery>;

  return queryRef ? (
    <DataTable
      dataColumns={dataColumns}
      resolvePath={(data: ProvenanceKnowledgeSightingsLines_data$data) => data.stixSightingRelationships?.edges?.map((edge) => edge?.node)}
      storageKey={storageKey}
      initialValues={initialValues}
      contextFilters={contextFilters}
      lineFragment={provenanceKnowledgeSightingsLineFragment}
      preloadedPaginationProps={preloadedPaginationProps}
      emptyStateMessage={hasUserFilters ? t_i18n('No result for these filters') : emptyMessage}
      exportContext={{ entity_type: 'stix-sighting-relationship' }}
      availableEntityTypes={['stix-sighting-relationship']}
      actions={(row: { id: string }) => <ProvenanceSourcesAction id={row.id} onChange={refresh} />}
    />
  ) : null;
};

export default ProvenanceKnowledgeSightings;
