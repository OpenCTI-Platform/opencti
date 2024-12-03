import React from 'react';
import { graphql } from 'react-relay';
import ManagementMenu from '@components/data/ManagementMenu';
import { ManagementDefinitionsLinesPaginationQuery } from '@components/data/__generated__/ManagementDefinitionsLinesPaginationQuery.graphql';
import { ManagementDefinitionsLines_data$data } from '@components/data/__generated__/ManagementDefinitionsLines_data.graphql';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import useHelper from '../../../utils/hooks/useHelper';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useAuth from '../../../utils/hooks/useAuth';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';

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
    creators {
        id
        name
    }
      }
`;

const managementDefinitionsLinesFragment = graphql`
    fragment ManagementDefinitionsLines_data on Query
    @argumentDefinitions(
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
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_stixCoreObjectsRestricted") {
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
  const { isFeatureEnable } = useHelper();
  const isNewManagementScreensEnables = isFeatureEnable('NEW_MANAGEMENT_SCREENS');
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['entity_type'], ['Stix-Core-Object']),
    },
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: false,
  };
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<ManagementDefinitionsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('Stix-Core-Object', viewStorage.filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };
  const queryRef = useQueryLoading(
    managementDefinitionsLinesPaginationQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: managementDefinitionsLinesPaginationQuery,
    linesFragment: managementDefinitionsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ManagementDefinitionsLinesPaginationQuery>;
  return (
    <div data-testid='data-management-page'>
      <Breadcrumbs elements={[
        { label: t_i18n('Data') },
        { label: t_i18n('Management') },
        { label: t_i18n('Restricted entities'), current: true },
      ]}
      />
      {isNewManagementScreensEnables && (
        <ManagementMenu/>
      )}
      {queryRef && (
        <DataTable
          dataColumns={{ entity_type: {
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
            isSortable: true,
            percentWidth: 10,
          },
          created_at: {
            percentWidth: 20,
          },
          objectMarking: {
            percentWidth: 10,
            isSortable: isRuntimeSort,
          } }}
          resolvePath={(data: ManagementDefinitionsLines_data$data) => data.stixCoreObjectsRestricted?.edges?.map((e) => e?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={managementDefinitionLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          toolbarFilters={contextFilters}
          // entityTypes={['Stix-Core-Object']}
          searchContextFinal={{ entityTypes: ['Stix-Core-Object'] }}
        />
      )}
    </div>
  );
};

export default Management;
