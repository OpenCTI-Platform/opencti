import React from 'react';
import { graphql } from 'react-relay';
import ManagementMenu from '@components/data/ManagementMenu';
import {
  ManagementDefinitionsLinesPaginationQuery,
  ManagementDefinitionsLinesPaginationQuery$variables,
} from '@components/data/__generated__/ManagementDefinitionsLinesPaginationQuery.graphql';
import { ManagementDefinitionsLines_data$data } from '@components/data/__generated__/ManagementDefinitionsLines_data.graphql';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useHelper from '../../../utils/hooks/useHelper';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useAuth from '../../../utils/hooks/useAuth';
import { addFilter, emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';

const LOCAL_STORAGE_KEY = 'restrictedEntities';

export const managementDefinitionsLinesPaginationQuery = graphql`
  query ManagementDefinitionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    ) {
      ...ManagementDefinitionsLines_data
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

const managementDefinitionLineFragment = graphql`
  fragment ManagementDefinitionsLine_node on StixCoreObject{
    id
    entity_type
    created_at
    updated_at
    ... on StixObject {
      representative {
        main
        secondary
      }
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
      created
      modified
    }
      objectLabel {
        id
        value
        color
      }
    creators {
      id
      name
    }
  }
`;

const managementDefinitionsLinesFragment = graphql`
  fragment ManagementDefinitionsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCoreObjectsOrdering"
      defaultValue: entity_type
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ManagementDefinitionsLinesRefetchQuery") {
    stixCoreObjectsRestricted(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) 
    @connection(key: "Pagination_stixCoreObjectsRestricted") {
      edges {
        node {
          id
          entity_type
          ...ManagementDefinitionsLine_node
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

const Management = () => {
  const { t_i18n } = useFormatter();

  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable();

  const { isFeatureEnable } = useHelper();
  const isRightMenuManagementEnable = isFeatureEnable('DATA_MANAGEMENT_RIGHT_MENU');

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: true,
    numberOfElements: {
      number: 0,
      symbol: '',
    },
  };

  const {
    viewStorage: { filters },
    paginationOptions,
    helpers,
  } = usePaginationLocalStorage<ManagementDefinitionsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Domain-Object', filters);
  const toolbarFilters = addFilter(contextFilters, 'authorized_members.id', [], 'not_nil');

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };

  const dataColumns = {
    entity_type: {
      percentWidth: 20,
      isSortable: true,
    },
    name: {
      percentWidth: 20,
    },
    createdBy: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    creator: {
      isSortable: isRuntimeSort,
      percentWidth: 10,
    },
    objectLabel: {
      percentWidth: 10,
    },
    created_at: {
      percentWidth: 20,
    },
    objectMarking: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
  };

  const queryRef = useQueryLoading(
    managementDefinitionsLinesPaginationQuery,
    { ...queryPaginationOptions, count: 25 },
  );

  const preloadedPaginationProps = {
    linesQuery: managementDefinitionsLinesPaginationQuery,
    linesFragment: managementDefinitionsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjectsRestricted', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ManagementDefinitionsLinesPaginationQuery>;

  return (
    <div data-testid='data-management-page'>
      <div style={{ paddingRight: isRightMenuManagementEnable ? '200px' : 0 }}>
        <Breadcrumbs elements={[
          { label: t_i18n('Data') },
          { label: t_i18n('Restriction') },
          { label: t_i18n('Restricted entities'), current: true },
        ]}
        />
        {isRightMenuManagementEnable && (
          <ManagementMenu/>
        )}
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: ManagementDefinitionsLines_data$data) => data.stixCoreObjectsRestricted?.edges?.map((e) => e?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            lineFragment={managementDefinitionLineFragment}
            preloadedPaginationProps={preloadedPaginationProps}
            toolbarFilters={toolbarFilters}
            entityTypes={['Stix-Core-Object']}
            searchContextFinal={{ entityTypes: ['Stix-Core-Object'] }}
            removeAuthMembersEnabled={true}
          />
        )}
      </div>
    </div>
  );
};

export default Management;
