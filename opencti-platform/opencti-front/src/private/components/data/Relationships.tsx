import React from 'react';
import { graphql } from 'react-relay';
import {
  RelationshipsStixCoreRelationshipsLinesPaginationQuery,
  RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/data/__generated__/RelationshipsStixCoreRelationshipsLinesPaginationQuery.graphql';
import { RelationshipsStixCoreRelationshipsLines_data$data } from '@components/data/__generated__/RelationshipsStixCoreRelationshipsLines_data.graphql';
import { AutoFix } from 'mdi-material-ui';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import ItemIcon from '../../../components/ItemIcon';
import { itemColor } from '../../../utils/Colors';
import ItemEntityType from '../../../components/ItemEntityType';

const LOCAL_STORAGE_KEY = 'relationships';

const relationshipsStixCoreRelationshipsLineFragment = graphql`
  fragment RelationshipsStixCoreRelationshipLine_node on StixCoreRelationship {
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

const relationshipsStixCoreRelationshipsLinesQuery = graphql`
  query RelationshipsStixCoreRelationshipsLinesPaginationQuery(
    $search: String
    $fromId: [String]
    $toId: [String]
    $fromTypes: [String]
    $toTypes: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreRelationshipsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...RelationshipsStixCoreRelationshipsLines_data
    @arguments(
      search: $search
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

export const relationshipsStixCoreRelationshipsLinesFragment = graphql`
  fragment RelationshipsStixCoreRelationshipsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    fromId: { type: "[String]" }
    toId: { type: "[String]" }
    fromTypes: { type: "[String]" }
    toTypes: { type: "[String]" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCoreRelationshipsOrdering"
      defaultValue: created
    }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "RelationshipsStixCoreRelationshipsLinesRefetchQuery") {
    stixCoreRelationships(
      search: $search
      fromId: $fromId
      toId: $toId
      fromTypes: $fromTypes
      toTypes: $toTypes
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
          ...RelationshipsStixCoreRelationshipLine_node
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

const Relationships = () => {
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['fromId', 'toId'], ['stix-core-relationship']),
    },
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
  };

  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('stix-core-relationship', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<RelationshipsStixCoreRelationshipsLinesPaginationQuery>(
    relationshipsStixCoreRelationshipsLinesQuery,
    queryPaginationOptions,
  );

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
    fromName: {},
    relationship_type: {},
    toType: {
      id: 'toType',
      label: 'To type',
      percentWidth: 10,
      isSortable: false,
      render: (node) => (
        <ItemEntityType inList showIcon entityType={node.to?.entity_type} isRestricted={!node.to} />
      ),
    },
    toName: {},
    createdBy: { percentWidth: 7, isSortable: isRuntimeSort },
    creator: { percentWidth: 7, isSortable: isRuntimeSort },
    created_at: { percentWidth: 12 },
    objectMarking: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationProps = {
    linesQuery: relationshipsStixCoreRelationshipsLinesQuery,
    linesFragment: relationshipsStixCoreRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<RelationshipsStixCoreRelationshipsLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Data') }, { label: t_i18n('Relationships'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: RelationshipsStixCoreRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((n) => n.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={relationshipsStixCoreRelationshipsLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          exportContext={{ entity_type: 'stix-core-relationship' }}
        />
      )}
    </>
  );
};

export default Relationships;
