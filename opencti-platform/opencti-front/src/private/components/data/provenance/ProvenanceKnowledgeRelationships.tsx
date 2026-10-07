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
  ProvenanceKnowledgeRelationshipsLinesPaginationQuery,
  ProvenanceKnowledgeRelationshipsLinesPaginationQuery$variables,
} from './__generated__/ProvenanceKnowledgeRelationshipsLinesPaginationQuery.graphql';
import { ProvenanceKnowledgeRelationshipsLines_data$data } from './__generated__/ProvenanceKnowledgeRelationshipsLines_data.graphql';

const provenanceKnowledgeRelationshipsLineFragment = graphql`
  fragment ProvenanceKnowledgeRelationshipsLine_node on StixCoreRelationship {
    id
    entity_type
    parent_types
    relationship_type
    created_at
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

const provenanceKnowledgeRelationshipsLinesQuery = graphql`
  query ProvenanceKnowledgeRelationshipsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ProvenanceKnowledgeRelationshipsLines_data
    @arguments(search: $search, count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
  }
`;

const provenanceKnowledgeRelationshipsLinesFragment = graphql`
  fragment ProvenanceKnowledgeRelationshipsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCoreRelationshipsOrdering", defaultValue: last_asserted_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ProvenanceKnowledgeRelationshipsLinesRefetchQuery") {
    stixCoreRelationships(search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
    @connection(key: "Pagination_provenance_stixCoreRelationships") {
      edges {
        node {
          id
          ...ProvenanceKnowledgeRelationshipsLine_node
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

interface ProvenanceKnowledgeRelationshipsProps {
  storageKey: string;
  // Fixed provenance filter of the view (stale knowledge, conflicts), not editable by the user
  fixedFilters: FilterGroup;
  withConflicts?: boolean;
  // Shown when nothing matches the fixed filter (no conflict, no stale knowledge)
  emptyMessage: string;
}

const ProvenanceKnowledgeRelationships = ({ storageKey, fixedFilters, withConflicts = false, emptyMessage }: ProvenanceKnowledgeRelationshipsProps) => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'last_asserted_at',
    orderAsc: true,
    openExports: false,
  };
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<ProvenanceKnowledgeRelationshipsLinesPaginationQuery$variables>(
    storageKey,
    initialValues,
  );
  const hasUserFilters = isFilterGroupNotEmpty(viewStorage.filters) || !!viewStorage.searchTerm;
  const userFilters = useBuildEntityTypeBasedFilterContext('stix-core-relationship', viewStorage.filters);
  const contextFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [fixedFilters, userFilters as FilterGroup] };
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as ProvenanceKnowledgeRelationshipsLinesPaginationQuery$variables;
  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<ProvenanceKnowledgeRelationshipsLinesPaginationQuery>(
    provenanceKnowledgeRelationshipsLinesQuery,
    queryPaginationOptions,
  );
  const refresh = () => loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });

  const dataColumns: DataTableProps['dataColumns'] = {
    fromType: { percentWidth: 8 },
    fromName: { percentWidth: withConflicts ? 12 : 17 },
    relationship_type: { percentWidth: 10 },
    toType: { percentWidth: 8 },
    toName: { percentWidth: withConflicts ? 12 : 17 },
    ...(withConflicts ? { conflict_fields: { ...conflictingFieldsColumn, percentWidth: 12 } } : {}),
    corroboration_count: { percentWidth: 11 },
    freshness_days: { percentWidth: 9 },
    last_asserted_at: { percentWidth: withConflicts ? 10 : 11 },
    objectMarking: { percentWidth: withConflicts ? 8 : 9, isSortable: false },
  };

  const preloadedPaginationProps = {
    linesQuery: provenanceKnowledgeRelationshipsLinesQuery,
    linesFragment: provenanceKnowledgeRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ProvenanceKnowledgeRelationshipsLinesPaginationQuery>;

  return queryRef ? (
    <DataTable
      dataColumns={dataColumns}
      resolvePath={(data: ProvenanceKnowledgeRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((edge) => edge?.node)}
      storageKey={storageKey}
      initialValues={initialValues}
      contextFilters={contextFilters}
      lineFragment={provenanceKnowledgeRelationshipsLineFragment}
      preloadedPaginationProps={preloadedPaginationProps}
      emptyStateMessage={hasUserFilters ? t_i18n('No result for these filters') : emptyMessage}
      exportContext={{ entity_type: 'stix-core-relationship' }}
      availableEntityTypes={['stix-core-relationship']}
      actions={(row: { id: string }) => <ProvenanceSourcesAction id={row.id} onChange={refresh} />}
    />
  ) : null;
};

export default ProvenanceKnowledgeRelationships;
