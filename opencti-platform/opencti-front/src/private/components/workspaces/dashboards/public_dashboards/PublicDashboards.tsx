import React from 'react';
import { graphql } from 'react-relay';
import PublicDashboardLineActions from './PublicDashboardLineActions';
import PublicDashboardCreation from './PublicDashboardCreation';
import { useFormatter } from '../../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../../utils/filters/filtersUtils';
import DataTable from '../../../../../components/dataGrid/DataTable';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import ItemBoolean from '../../../../../components/ItemBoolean';
import { DataTableProps } from '../../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../../components/dataGrid/dataTableUtils';
import Security from '../../../../../utils/Security';
import { EXPLORE_EXUPDATE_PUBLISH } from '../../../../../utils/hooks/useGranted';
import useHelper from '../../../../../utils/hooks/useHelper';
import { PublicDashboardsListQuery, PublicDashboardsListQuery$variables } from './__generated__/PublicDashboardsListQuery.graphql';
import { PublicDashboardsFragment$data } from './__generated__/PublicDashboardsFragment.graphql';
import useConnectedDocumentModifier from '../../../../../utils/hooks/useConnectedDocumentModifier';

const publicDashboardFragment = graphql`
  fragment PublicDashboards_PublicDashboard on PublicDashboard {
    id
    uri_key
    enabled
    entity_type
    name
    owner {
      name
    }
    dashboard {
      name
      id
      currentUserAccessRight
    }
    allowed_markings {
      id
      definition
      definition_type
      x_opencti_color
      x_opencti_order
    }
  }
`;

export const publicDashboardsFragment = graphql`
  fragment PublicDashboardsFragment on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "PublicDashboardsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PublicDashboardsRefetchQuery") {
    publicDashboards(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_publicDashboards") {
      edges {
        node {
          id
          ...PublicDashboards_PublicDashboard
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

const publicDashboardsListQuery = graphql`
  query PublicDashboardsListQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: PublicDashboardsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup)
  {
    ...PublicDashboardsFragment
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

const LOCAL_STORAGE_KEY = 'PublicDashboard';

const PublicDashboards = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Public dashboards'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<PublicDashboardsListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext(
    'PublicDashboard',
    viewStorage.filters,
  );

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as PublicDashboardsListQuery$variables;

  const queryRef = useQueryLoading<PublicDashboardsListQuery>(
    publicDashboardsListQuery,
    queryPaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      percentWidth: 18,
    },
    uri_key: {
      id: 'uri_key',
      percentWidth: 18,
      label: 'URI key',
      isSortable: true,
      render: ({ uri_key }) => defaultRender(uri_key),
    },
    dashboard: {
      id: 'dashboard',
      percentWidth: 18,
      label: 'Dashboard',
      isSortable: false,
      render: ({ dashboard }) => defaultRender(dashboard.name),
    },
    enabled: {
      id: 'enabled',
      percentWidth: 15,
      label: 'Enabled',
      isSortable: true,
      render: ({ enabled }) => (
        <ItemBoolean
          status={enabled}
          label={enabled ? t_i18n('Enabled') : t_i18n('Disabled')}
        />
      ),
    },
    user_id: {
      id: 'owner',
      percentWidth: 15,
      label: 'Shared by',
      isSortable: true,
      render: ({ owner }) => defaultRender(owner.name),
    },
    allowed_markings: {
      id: 'allowed_markings',
    },
  };

  return (
    <>
      <Breadcrumbs
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Public dashboards'), current: true },
        ]}

      />
      {queryRef && (
        <DataTable
          disableNavigation
          dataColumns={dataColumns}
          resolvePath={(data: PublicDashboardsFragment$data) => {
            return data.publicDashboards?.edges?.map((n) => n?.node);
          }}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={{
            linesQuery: publicDashboardsListQuery,
            linesFragment: publicDashboardsFragment,
            queryRef,
            nodePath: ['publicDashboards', 'pageInfo', 'globalCount'],
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={publicDashboardFragment}
          entityTypes={['PublicDashboard']}
          searchContextFinal={{ entityTypes: ['PublicDashboard'] }}
          actions={(row) => (
            <PublicDashboardLineActions
              publicDashboard={row}
              paginationOptions={queryPaginationOptions}
            />
          )}
          createButton={isFeatureEnable('FAB_REPLACEMENT') && (
            <Security needs={[EXPLORE_EXUPDATE_PUBLISH]}>
              <PublicDashboardCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
          taskScope='PUBLIC_DASHBOARD'
        />
      )}

      {!isFeatureEnable('FAB_REPLACEMENT') && (
        <Security needs={[EXPLORE_EXUPDATE_PUBLISH]}>
          <PublicDashboardCreation
            paginationOptions={queryPaginationOptions}
          />
        </Security>
      )}
    </>
  );
};

export default PublicDashboards;
