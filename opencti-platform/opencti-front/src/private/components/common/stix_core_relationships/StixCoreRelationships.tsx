import React, { FunctionComponent } from 'react';
import { AutoFix, ProgressWrench, RelationManyToMany } from 'mdi-material-ui';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewColumnOutlined } from '@mui/icons-material';
import FiligranIcon from '@components/common/FiligranIcon';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import { graphql } from 'react-relay';
import {
  StixCoreRelationshipsLinesPaginationQuery,
  StixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLinesPaginationQuery.graphql';
import { StixCoreRelationshipsLines_data$data } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLines_data.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import { itemColor } from '../../../../utils/Colors';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { PaginationOptions } from '../../../../components/list_lines';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreRelationshipsProps {
  storageKey: string;
  entityId: string;
  currentView?: string;
  paginationOptions: PaginationOptions;
  targetTypes: string[]
  direction: 'fromEntity' | 'toEntity' | 'all'
  relationshipTypes: string[]
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
    paginationOptions,
    targetTypes,
    direction,
    relationshipTypes,
  },
) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { t_i18n } = useFormatter();
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
      percentWidth: 25,
    },
    createdBy: { percentWidth: 10, isSortable: isRuntimeSort },
    creator: { percentWidth: 10, isSortable: isRuntimeSort },
    created_at: { percentWidth: 15 },
    objectMarking: { isSortable: isRuntimeSort },
  };

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
    view: currentView,
  };

  const { viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<StixCoreRelationshipsLinesPaginationQuery$variables>(
    storageKey,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  // Filters due to screen context
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const predefinedFilters = [{ key: 'relationship_type', values: relationshipTypes }];
  if (direction === 'all') {
    predefinedFilters.push({ key: 'fromOrToId', values: [entityId] });
    predefinedFilters.push({ key: 'elementWithTargetTypes', values: targetTypes });
  } else if (direction === 'toEntity') {
    predefinedFilters.push({ key: 'toId', values: [entityId] });
    // if (role) predefinedFilters.push({ key: 'toRole', values: [role] });
    predefinedFilters.push({ key: 'fromTypes', values: targetTypes });
  } else {
    predefinedFilters.push({ key: 'fromId', values: [entityId] });
    // if (role) predefinedFilters.push({ key: 'fromRole', values: [role] });
    predefinedFilters.push({ key: 'toTypes', values: targetTypes });
  }
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: predefinedFilters,
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
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
    <div
      style={{
        transform: 'translateY(-12px)',
      }}
    >      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: StixCoreRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((n) => n.node)}
        storageKey={storageKey}
        initialValues={initialValues}
        toolbarFilters={contextFilters}
        lineFragment={stixCoreRelationshipsFragment}
        preloadedPaginationProps={preloadedPaginationProps}
        exportContext={{ entity_type: 'Attack-Pattern' }}
        additionalHeaderButtons={[
          (<ToggleButton key="matrix" value="matrix" aria-label="matrix">
            <Tooltip title={t_i18n('Matrix view')}>
              <ViewColumnOutlined fontSize="small" color="primary" />
            </Tooltip>
          </ToggleButton>),
          (<Tooltip key="matrix-in-line" title={t_i18n('Matrix in line view')}>
            <ToggleButton key="matrix-in-line" value="matrix-in-line" aria-label="matrix-in-line">
              <FiligranIcon icon={ListViewIcon} size="small" color={currentView === 'matrix-in-line' ? 'secondary' : 'primary'} />
            </ToggleButton>
          </Tooltip>
          ),
          (<Tooltip key="list" title={t_i18n('Kill chain view')}>
            <ToggleButton key="list" value="list" aria-label="list">
              <FiligranIcon icon={SublistViewIcon} size="small" color={currentView === 'list' ? 'secondary' : 'primary'} />
            </ToggleButton>
          </Tooltip>
          ),
          (<ToggleButton key="courses-of-action" value="courses-of-action" aria-label="courses-of-action">
            <Tooltip title={t_i18n('Courses of action view')}>
              <ProgressWrench color={currentView === 'courses-of-action' ? 'secondary' : 'primary'} fontSize="small" />
            </Tooltip>
          </ToggleButton>),
          (<ToggleButton key="relationships" value="relationships" aria-label="relationships">
            <Tooltip title={t_i18n('Relationships view')}>
              <RelationManyToMany fontSize="small" color={currentView === 'relationships' ? 'secondary' : 'primary'}/>
            </Tooltip>
          </ToggleButton>),
        ]}
      />
    )}
    </div>
  );
};
export default StixCoreRelationships;
