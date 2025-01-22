import React from 'react';
import { useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { DraftSightingsLinesPaginationQuery, DraftSightingsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftSightingsLinesPaginationQuery.graphql';
import { DraftSightingsLines_data$data } from '@components/drafts/__generated__/DraftSightingsLines_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { truncate } from '../../../utils/String';
import { useFormatter } from '../../../components/i18n';

const draftSightingsLineFragment = graphql`
    fragment DraftSightings_node on StixSightingRelationship {
        id
        entity_type
        parent_types
        x_opencti_negative
        attribute_count
        confidence
        first_seen
        last_seen
        description
        draftVersion {
            draft_id
            draft_operation
        }
        status {
            id
            order
            template {
                name
                color
            }
        }
        workflowEnabled
        is_inferred
        x_opencti_inferences {
            rule {
                id
                name
            }
        }
        from {
            ... on StixDomainObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
            }
            ... on AttackPattern {
                name
                description
                x_mitre_id
                killChainPhases {
                    id
                    phase_name
                    x_opencti_order
                }
            }
            ... on Campaign {
                name
                description
            }
            ... on CourseOfAction {
                name
                description
            }
            ... on Individual {
                name
                description
            }
            ... on Organization {
                name
                description
            }
            ... on Sector {
                name
                description
            }
            ... on System {
                name
                description
            }
            ... on Indicator {
                name
                description
            }
            ... on Infrastructure {
                name
                description
            }
            ... on IntrusionSet {
                name
                description
            }
            ... on Position {
                name
                description
            }
            ... on City {
                name
                description
            }
            ... on AdministrativeArea {
                name
                description
            }
            ... on Country {
                name
                description
            }
            ... on Region {
                name
                description
            }
            ... on Malware {
                name
                description
            }
            ... on ThreatActor {
                name
                description
            }
            ... on Tool {
                name
                description
            }
            ... on Vulnerability {
                name
                description
            }
            ... on Incident {
                name
                description
            }
            ... on ObservedData {
                name
                first_observed
                last_observed
            }
            ... on StixCyberObservable {
                id
                entity_type
                parent_types
                created_at
                updated_at
                observable_value
            }
        }
        to {
            ... on StixObject {
                id
                entity_type
                parent_types
                created_at
                updated_at
            }
            ... on Individual {
                name
                description
            }
            ... on Organization {
                name
                description
            }
            ... on Sector {
                name
                description
            }
            ... on System {
                name
                description
            }
            ... on Position {
                name
                description
            }
            ... on City {
                name
                description
            }
            ... on AdministrativeArea {
                name
                description
            }
            ... on Country {
                name
                description
            }
            ... on Region {
                name
                description
            }
        }
    }
`;

const draftSightingsLinesQuery = graphql`
    query DraftSightingsLinesPaginationQuery(
        $draftId: String!
        $types: [String]
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: StixSightingRelationshipsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftSightingsLines_data
        @arguments(
            draftId: $draftId
            types: $types
            search: $search
            count: $count
            cursor: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        )
    }
`;

export const draftSightingsLinesFragment = graphql`
    fragment DraftSightingsLines_data on Query
    @argumentDefinitions(
        draftId: { type: "String!" }
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: {
            type: "StixSightingRelationshipsOrdering"
            defaultValue: first_seen
        }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftSightingsLinesRefetchQuery") {
        draftWorkspaceSightingRelationships(
            draftId: $draftId
            types: $types
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaceSightingRelationships") {
            edges {
                node {
                    ...DraftSightings_node
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

const LOCAL_STORAGE_KEY = 'draft_sightings';

const DraftSightings = () => {
  const { draftId } = useParams() as { draftId: string };
  const { t_i18n } = useFormatter();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['draft_change.draft_operation'], ['stix-core-relationship'], ['create', 'update', 'delete']),
    },
    searchTerm: '',
    sortBy: 'last_seen',
    orderAsc: false,
    openExports: false,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<DraftSightingsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('stix-sighting-relationship', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    draftId,
    filters: contextFilters,
  } as unknown as DraftSightingsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<DraftSightingsLinesPaginationQuery>(
    draftSightingsLinesQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    draftVersion: {
      isSortable: false,
      percentWidth: 10,
    },
    x_opencti_negative: {},
    attribute_count: {},
    name: {
      label: 'Name',
      percentWidth: 10,
      isSortable: false,
      render: ({ from }, { fd }) => (from !== null
        ? from.name
              || from.attribute_abstract
              || truncate(from.content, 30)
              || from.observable_value
              || `${fd(from.first_observed)} - ${fd(from.last_observed)}`
        : t_i18n('Restricted')),
    },
    entity_type: {
      label: 'Entity type',
      percentWidth: 10,
      isSortable: false,
      render: ({ from }) => (from !== null
        ? t_i18n(`entity_${from.entity_type}`)
        : t_i18n('Restricted')),
    },
    entity: {
      label: 'Entity',
      percentWidth: 10,
      isSortable: false,
      render: ({ to }, { fd }) => (to !== null
        ? to.name
              || to.attribute_abstract
              || truncate(to.content, 30)
              || to.observable_value
              || `${fd(to.first_observed)} - ${fd(to.last_observed)}`
        : t_i18n('Restricted')),
    },
    first_seen: {},
    last_seen: {},
    confidence: {},
    x_opencti_workflow_id: {},
  };

  const preloadedPaginationProps = {
    linesQuery: draftSightingsLinesQuery,
    linesFragment: draftSightingsLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaceSightingRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DraftSightingsLinesPaginationQuery>;

  return (
    <span data-testid="draft-relationships-page">
      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: DraftSightingsLines_data$data) => data.draftWorkspaceSightingRelationships?.edges?.map((n) => n?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        toolbarFilters={contextFilters}
        preloadedPaginationProps={preloadedPaginationProps}
        lineFragment={draftSightingsLineFragment}
        exportContext={{ entity_type: 'stix-sighting-relationship' }}
        redirectionModeEnabled
        disableSelectAll
      />
      )}
    </span>
  );
};

export default DraftSightings;
