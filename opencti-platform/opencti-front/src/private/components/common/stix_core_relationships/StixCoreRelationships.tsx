import React, { FunctionComponent, ReactElement } from 'react';
import { AutoFix } from 'mdi-material-ui';
import { graphql } from 'react-relay';
import { StixCoreRelationshipsLinesPaginationQuery, StixCoreRelationshipsLinesPaginationQuery$variables } from './__generated__/StixCoreRelationshipsLinesPaginationQuery.graphql';
import { StixCoreRelationshipsLines_data$data } from './__generated__/StixCoreRelationshipsLines_data.graphql';
import StixCoreRelationshipCreationFromEntity from './StixCoreRelationshipCreationFromEntity';
import useAuth from '../../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import { itemColor } from '../../../../utils/Colors';
import Security from '../../../../utils/Security';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';

interface StixCoreRelationshipsProps {
  storageKey: string;
  entityId: string;
  currentView?: string;
  viewButtons: ReactElement[];
  targetTypes: string[]
  direction: 'fromEntity' | 'toEntity' | 'all'
  relationshipTypes: string[]
  defaultStartTime: string;
  defaultStopTime: string;
}

export const stixCoreRelationshipsFragment = graphql`
  fragment StixCoreRelationships on StixCoreRelationship {
    id
    entity_type
    parent_types
    relationship_type
    confidence
    start_time
    stop_time
    description
    fromRole
    toRole
    created_at
    updated_at
    is_inferred
    draftVersion{
      draft_id
      draft_operation
    }
    createdBy {
      ... on Identity {
        name
      }
    }
    objectMarking {
      id
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
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
        created_at
        representative {
          main
        }
      }
      ... on StixCoreRelationship {
        created_at
        start_time
        stop_time
        created
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
        created_at
        representative {
          main
        }
      }
      ... on StixCoreRelationship {
        created_at
        start_time
        stop_time
        created
        representative {
            main
        }
      }
    }
  }
`;

export const stixCoreRelationshipsLinesQuery = graphql`
  query StixCoreRelationshipsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCoreRelationshipsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const stixCoreRelationshipsLinesFragment = graphql`
  fragment StixCoreRelationshipsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCoreRelationshipsOrdering"
      defaultValue: created
    }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "StixCoreRelationshipsLinesRefetchQuery") {
    stixCoreRelationships(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCoreRelationships") {
      edges {
        node {
          id
          entity_type
          created_at
          draftVersion{
            draft_id
            draft_operation
          }
          createdBy {
            ... on Identity {
            name
            }
          }
            objectMarking {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
            ...StixCoreRelationships
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

const StixCoreRelationships: FunctionComponent<StixCoreRelationshipsProps> = (
  {
    storageKey,
    entityId,
    currentView,
    viewButtons,
    targetTypes,
    direction,
    relationshipTypes,
    defaultStartTime,
    defaultStopTime,
  },
) => {
  const LOCAL_STORAGE_KEY = `${storageKey}-stix-core-relationships`;
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    is_inferred: {
      id: 'is_inferred',
      label: ' ',
      isSortable: false,
      percentWidth: 3,
      render: ({ is_inferred, entity_type }) => (is_inferred ? <AutoFix style={{ color: itemColor(entity_type) }} /> : <ItemIcon type={entity_type} />),
    },
    fromType: {
      id: 'fromType',
      label: 'From type',
      percentWidth: 10,
      isSortable: false,
      render: (node) => (
        <ItemEntityType inList showIcon entityType={node.from?.entity_type} isRestricted={!node.from} />
      ),
    },
    relationship_type: {
      percentWidth: 10,
    },
    toType: {
      id: 'toType',
      label: 'To type',
      percentWidth: 10,
      isSortable: false,
      render: (node) => (
        <ItemEntityType inList showIcon entityType={node.to?.entity_type} isRestricted={!node.to} />
      ),
    },
    toName: {
      percentWidth: 24,
    },
    createdBy: { percentWidth: 10, isSortable: isRuntimeSort },
    creator: { percentWidth: 10, isSortable: isRuntimeSort },
    created_at: { percentWidth: 15 },
    objectMarking: { isSortable: isRuntimeSort },
  };

  const initialValues = {
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
    view: currentView ?? 'relationships',
  };

  const { paginationOptions, viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<StixCoreRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );
  const {
    filters,
  } = viewStorage;

  // Filters due to screen context
  const userFilters = useBuildEntityTypeBasedFilterContext('stix-core-relationship', filters);
  const predefinedFilters = [{ key: 'relationship_type', values: relationshipTypes }];
  if (direction === 'all') {
    predefinedFilters.push({ key: 'fromOrToId', values: [entityId] });
    predefinedFilters.push({ key: 'elementWithTargetTypes', values: targetTypes });
  } else if (direction === 'toEntity') {
    predefinedFilters.push({ key: 'toId', values: [entityId] });
    predefinedFilters.push({ key: 'fromTypes', values: targetTypes });
  } else {
    predefinedFilters.push({ key: 'fromId', values: [entityId] });
    predefinedFilters.push({ key: 'toTypes', values: targetTypes });
  }
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: predefinedFilters,
    filterGroups: isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as StixCoreRelationshipsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<StixCoreRelationshipsLinesPaginationQuery>(
    stixCoreRelationshipsLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipsLinesQuery,
    linesFragment: stixCoreRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipsLinesPaginationQuery>;

  return (
    <>
      <div style={{ marginTop: -12 }}>
        {queryRef && (
          <DataTable
            variant={DataTableVariant.inline}
            dataColumns={dataColumns}
            resolvePath={(data: StixCoreRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((n) => n.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            toolbarFilters={contextFilters}
            lineFragment={stixCoreRelationshipsFragment}
            preloadedPaginationProps={preloadedPaginationProps}
            exportContext={{ entity_type: 'stix-core-relationship' }}
            additionalHeaderButtons={[...viewButtons]}
          />
        )}
      </div>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <StixCoreRelationshipCreationFromEntity
          entityId={entityId}
          isRelationReversed={false}
          paddingRight={220}
          targetStixDomainObjectTypes={['Attack-Pattern']}
          paginationOptions={queryPaginationOptions}
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
        />
      </Security>
    </>
  );
};
export default StixCoreRelationships;
