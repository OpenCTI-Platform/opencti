import React from 'react';
import { graphql } from 'react-relay';
import {
  StixSightingRelationshipsLinesPaginationQuery,
  StixSightingRelationshipsLinesPaginationQuery$variables,
} from '@components/events/__generated__/StixSightingRelationshipsLinesPaginationQuery.graphql';
import { StixSightingRelationshipsLines_data$data } from '@components/events/__generated__/StixSightingRelationshipsLines_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { truncate } from '../../../utils/String';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';

const stixSightingsLineFragment = graphql`
  fragment StixSightingRelationshipsLine_node on StixSightingRelationship {
    id
    entity_type
    parent_types
    x_opencti_negative
    attribute_count
    confidence
    first_seen
    last_seen
    description
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

const stixSightingRelationshipsLinesQuery = graphql`
  query StixSightingRelationshipsLinesPaginationQuery(
    $fromId: StixRef
    $toId: StixRef
    $toTypes: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixSightingRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixSightingRelationshipsLines_data
    @arguments(
      fromId: $fromId
      toId: $toId
      toTypes: $toTypes
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const stixSightingRelationshipsLinesFragment = graphql`
  fragment StixSightingRelationshipsLines_data on Query
  @argumentDefinitions(
    fromId: { type: "StixRef" }
    toId: { type: "StixRef" }
    toTypes: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixSightingRelationshipsOrdering"
      defaultValue: first_seen
    }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "StixSightingRelationshipsLinesRefetchQuery") {
    stixSightingRelationships(
      fromId: $fromId
      toId: $toId
      toTypes: $toTypes
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixSightingRelationships") {
      edges {
        node {
          id
          ...StixSightingRelationshipsLine_node
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

const LOCAL_STORAGE_KEY = 'stixSightingRelationships';

const StixSightingRelationships = () => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['toSightingId', 'x_opencti_negative'], ['stix-sighting-relationship']),
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
  } = usePaginationLocalStorage<StixSightingRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('stix-sighting-relationship', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as StixSightingRelationshipsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<StixSightingRelationshipsLinesPaginationQuery>(
    stixSightingRelationshipsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: stixSightingRelationshipsLinesQuery,
    linesFragment: stixSightingRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixSightingRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixSightingRelationshipsLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    x_opencti_negative: {},
    attribute_count: {},
    name: {
      label: 'Name',
      percentWidth: 15,
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
      percentWidth: 12,
      isSortable: false,
      render: ({ from }) => (from !== null
        ? t_i18n(`entity_${from.entity_type}`)
        : t_i18n('Restricted')),
    },
    entity: {
      label: 'Entity',
      percentWidth: 12,
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

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Events') }, { label: t_i18n('Sightings'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixSightingRelationshipsLines_data$data) => data.stixSightingRelationships?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={stixSightingsLineFragment}
          exportContext={{ entity_type: 'stix-sighting-relationship' }}
        />
      )}
    </>
  );
};

export default StixSightingRelationships;
