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
  const { isFeatureEnable } = useHelper();
  const isNewManagementScreensEnables = isFeatureEnable('NEW_MANAGEMENT_SCREENS');

  const initialValues = {
    searchTerm: '',
    sortBy: 'entity_type',
    orderAsc: false,
  };
  const { paginationOptions, helpers } = usePaginationLocalStorage<ManagementDefinitionsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const queryPaginationOptions = {
    ...paginationOptions,
  };
  const queryRef = useQueryLoading(managementDefinitionsLinesPaginationQuery, queryPaginationOptions);
  console.log('QUERY', queryRef);

  const preloadedPaginationProps = {
    linesQuery: managementDefinitionsLinesPaginationQuery,
    linesFragment: managementDefinitionsLinesFragment,
    queryRef,
    nodePath: ['stixCoreObjects'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ManagementDefinitionsLinesPaginationQuery>;
  return (
    <div data-testid='data-management-page'>
      <Breadcrumbs elements={[{ label: t_i18n('Data') }, { label: t_i18n('Management') }, { label: t_i18n('Restricted entities'), current: true }]}/>
      {isNewManagementScreensEnables && (
      <ManagementMenu />
      )}
      {queryRef && (
      <DataTable
        dataColumns={{
          entity_type: {
            percentWidth: 20,
            isSortable: false,
          },
          name: { percentWidth: 50 },
          objectMarking: {
            percentWidth: 15,
          },
        }}
        resolvePath={(data: ManagementDefinitionsLines_data$data) => data.stixCoreObjectsRestricted?.edges?.map((e) => e?.node)}
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={initialValues}
        lineFragment={managementDefinitionLineFragment}
        preloadedPaginationProps={preloadedPaginationProps}
        // entityTypes={['Stix-Core-Object']}
        // searchContextFinal={{ entityTypes: ['Stix-Core-Object'] }}
      />
      )}
    </div>
  );
};

export default Management;
