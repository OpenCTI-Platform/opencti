import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import {
  EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery,
  EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery$variables,
} from '@components/common/stix_core_relationships/views/indicators/__generated__/EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery.graphql';
import {
  EntityStixCoreRelationshipsIndicatorsEntitiesView_data$data,
} from '@components/common/stix_core_relationships/views/indicators/__generated__/EntityStixCoreRelationshipsIndicatorsEntitiesView_data.graphql';
import Tooltip from '@mui/material/Tooltip';
import { LibraryBooksOutlined } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import { Group, RelationManyToMany } from 'mdi-material-ui';
import Security from '../../../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../../../utils/hooks/useGranted';
import StixCoreRelationshipCreationFromEntity from '../../StixCoreRelationshipCreationFromEntity';
import { PaginationLocalStorage, usePaginationLocalStorage } from '../../../../../../utils/hooks/useLocalStorage';
import { PaginationOptions } from '../../../../../../components/list_lines';
import useAuth from '../../../../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../../../utils/filters/filtersUtils';
import { FilterGroup } from '../../../../../../utils/filters/filtersHelpers-types';
import DataTable from '../../../../../../components/dataGrid/DataTable';
import { DataTableVariant } from '../../../../../../components/dataGrid/dataTableTypes';
import { useQueryLoadingWithLoadQuery } from '../../../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../../../utils/hooks/usePreloadedPaginationFragment';
import { useFormatter } from '../../../../../../components/i18n';

interface EntityStixCoreRelationshipsIndicatorsEntitiesViewProps {
  entityId: string
  relationshipTypes: string[]
  defaultStartTime: string
  defaultStopTime: string
  localStorage: PaginationLocalStorage<PaginationOptions>
  isRelationReversed: boolean
  currentView: string
}

export const entityStixCoreRelationshipsIndicatorsEntitiesViewQuery = graphql`
  query EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...EntityStixCoreRelationshipsIndicatorsEntitiesView_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

export const entityStixCoreRelationshipsIndicatorsEntitiesViewFragment = graphql`
  fragment EntityStixCoreRelationshipsIndicatorsEntitiesView_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    filters: { type: "FilterGroup" }
    orderBy: { type: "IndicatorsOrdering", defaultValue: valid_from }
    orderMode: { type: "OrderingMode", defaultValue: desc }
  )
  @refetchable(queryName: "EntityStixCoreRelationshipsIndicatorsEntitiesViewRefetchQuery") {
    indicators(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_indicators") {
      edges {
        node {
          id
          ...EntityStixCoreRelationshipsIndicatorsEntitiesViewLine_node
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

export const entityStixCoreRelationshipsIndicatorsEntitiesViewLineFragment = graphql`
  fragment EntityStixCoreRelationshipsIndicatorsEntitiesViewLine_node on Indicator {
    id
    entity_type
    name
    pattern_type
    description
    valid_from
    valid_until
    created
    created_at
    x_opencti_score
    x_opencti_main_observable_type
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

const EntityStixCoreRelationshipsIndicatorsEntitiesView: FunctionComponent<EntityStixCoreRelationshipsIndicatorsEntitiesViewProps> = ({
  entityId,
  relationshipTypes,
  defaultStartTime,
  defaultStopTime,
  localStorage,
  isRelationReversed,
  currentView,
}) => {
  const { t_i18n } = useFormatter();
  const { viewStorage, helpers: storageHelpers, localStorageKey } = localStorage;
  const {
    filters,
    searchTerm,
    orderAsc,
    openExports,
  } = viewStorage;

  const { platformModuleHelpers } = useAuth();
  const isRuntimeSort = platformModuleHelpers.isRuntimeFieldEnable();
  const dataColumns = {
    pattern_type: { percentWidth: 10 },
    name: { percentWidth: 30 },
    objectLabel: { percentWidth: 15 },
    created_at: { percentWidth: 15 },
    valid_until: { percentWidth: 20 },
    objectMarking: { percentWidth: 10, isSortable: isRuntimeSort },
  };

  const initialValues = {
    search: searchTerm,
    orderBy: 'name',
    orderMode: orderAsc ? 'asc' : 'desc',
    filters: emptyFilterGroup,
    view: currentView ?? 'entities',
  };

  const { paginationOptions } = usePaginationLocalStorage<EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery$variables>(
    localStorageKey,
    initialValues,
    true,
  );

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['Indicator']);
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [
      { key: 'entity_type', values: ['Indicator'], mode: 'or', operator: 'eq' },
      {
        key: 'regardingOf',
        values: [
          { key: 'id', values: [entityId] },
          { key: 'relationship_type', values: ['indicates'] },
        ],
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery$variables;

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery>(
    entityStixCoreRelationshipsIndicatorsEntitiesViewQuery,
    queryPaginationOptions,
  );

  const refetch = React.useCallback(() => {
    loadQuery(queryPaginationOptions, { fetchPolicy: 'store-and-network' });
  }, [queryRef]);

  const preloadedPaginationProps = {
    linesQuery: entityStixCoreRelationshipsIndicatorsEntitiesViewQuery,
    linesFragment: entityStixCoreRelationshipsIndicatorsEntitiesViewFragment,
    queryRef,
    nodePath: ['indicators', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<EntityStixCoreRelationshipsIndicatorsEntitiesViewQuery>;

  const entitiesViewButton = (
    <ToggleButton value="entities" aria-label="entities" onClick={() => storageHelpers.handleChangeView('entities')}>
      <Tooltip title={t_i18n('Entities view')}>
        <LibraryBooksOutlined
          fontSize="small"
          color={currentView === 'entities' ? 'secondary' : 'primary'}
        />
      </Tooltip>
    </ToggleButton>
  );
  const relationshipsView = (
    <ToggleButton value="relationships" aria-label="relationships" onClick={() => storageHelpers.handleChangeView('relationships')}>
      <Tooltip title={t_i18n('Relationships view')}>
        <RelationManyToMany
          fontSize="small"
          color={currentView === 'relationships' ? 'secondary' : 'primary'}
        />
      </Tooltip>
    </ToggleButton>
  );
  const knowledgeFromRelatedContainersView = (
    <ToggleButton value="contextual" aria-label="contextual" onClick={() => storageHelpers.handleChangeView('contextual')}>
      <Tooltip
        title={t_i18n('Knowledge from related containers view')}
      >
        <Group
          fontSize="small"
          color={currentView === 'contextual' || !currentView ? 'secondary' : 'primary'}
        />
      </Tooltip>
    </ToggleButton>
  );

  const viewButtons = [entitiesViewButton, relationshipsView, knowledgeFromRelatedContainersView];

  return (
    <>
      {queryRef && (
      <DataTable
        variant={DataTableVariant.inline}
        dataColumns={dataColumns}
        resolvePath={(data: EntityStixCoreRelationshipsIndicatorsEntitiesView_data$data) => (data.indicators?.edges ?? []).map((n) => n?.node)}
        storageKey={localStorageKey}
        initialValues={initialValues}
        toolbarFilters={contextFilters}
        preloadedPaginationProps={preloadedPaginationProps}
        lineFragment={entityStixCoreRelationshipsIndicatorsEntitiesViewLineFragment}
        exportContext={{ entity_type: 'Indicator' }}
        additionalHeaderButtons={[...viewButtons]}
      />
      )}
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <StixCoreRelationshipCreationFromEntity
          entityId={entityId}
          isRelationReversed={isRelationReversed}
          targetStixDomainObjectTypes={['Indicator']}
          allowedRelationshipTypes={relationshipTypes}
          paginationOptions={paginationOptions}
          openExports={openExports}
          paddingRight={220}
          onCreate={refetch}
          connectionKey="Pagination_indicators"
          defaultStartTime={defaultStartTime}
          defaultStopTime={defaultStopTime}
        />
      </Security>
    </>
  );
};
export default EntityStixCoreRelationshipsIndicatorsEntitiesView;
