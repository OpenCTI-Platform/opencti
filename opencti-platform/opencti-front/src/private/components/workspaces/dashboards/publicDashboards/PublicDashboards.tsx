import React, { useState } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined } from '@mui/icons-material';
import { graphql } from 'react-relay';
import { PublicDashboardsListQuery, PublicDashboardsListQuery$variables } from '@components/workspaces/dashboards/__generated__/PublicDashboardsListQuery.graphql';
import { PublicDashboardsFragment$data } from '@components/workspaces/dashboards/__generated__/PublicDashboardsFragment.graphql';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { PopoverProps } from '@mui/material/Popover';
import { useFormatter } from '../../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../../utils/filters/filtersUtils';
import DataTable from '../../../../../components/dataGrid/DataTable';
import Breadcrumbs from '../../../../../components/Breadcrumbs';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../../../utils/hooks/useLocalStorage';
import ItemBoolean from '../../../../../components/ItemBoolean';
import { DataTableProps } from '../../../../../components/dataGrid/dataTableTypes';
import { textInTooltip } from '../../../../../components/dataGrid/dataTableUtils';
import { copyToClipboard } from '../../../../../utils/utils';

const publicDashboardFragment = graphql`
  fragment PublicDashboards_PublicDashboard on PublicDashboard {
    id
    uri_key
    enabled
    name
    owner {
      name
    }
    dashboard {
      name
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
  const contextFilters = useBuildEntityTypeBasedFilterContext('PublicDashboard', viewStorage.filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as PublicDashboardsListQuery$variables;

  const queryRef = useQueryLoading<PublicDashboardsListQuery>(
    publicDashboardsListQuery,
    queryPaginationOptions,
  );
  const [selectedUriKey, setSelectedUriKey] = useState('');
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const handleOpen = (event: React.MouseEvent, uri_key: string) => {
    setAnchorEl(event.currentTarget);
    setSelectedUriKey(uri_key);
  };
  const handleClose = () => {
    setAnchorEl(null);
    setSelectedUriKey('');
  };

  const copyLinkUrl = (uriKey: string) => {
    copyToClipboard(
      t_i18n,
      `${window.location.origin}/public/dashboard/${uriKey.toLowerCase()}`,
    );
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      flexSize: 18,
      label: 'Name',
    },
    uri_key: {
      id: 'uri_key',
      flexSize: 18,
      label: 'URI Key',
      render: ({ uri_key }, h) => textInTooltip(uri_key, h),
    },
    dashboard: {
      id: 'dashboard',
      flexSize: 18,
      label: 'Dashboard',
      isSortable: false,
      render: ({ dashboard }, h) => textInTooltip(dashboard.name, h),
    },
    allowed_markings: {
      id: 'allowed_markings',
      flexSize: 16,
      label: 'Max markings shared',
      isSortable: false,
    },
    enabled: {
      id: 'enabled',
      flexSize: 15,
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
      flexSize: 15,
      label: 'Shared by',
      isSortable: true,
      render: ({ owner }, h) => textInTooltip(owner.name, h),
    },
  };

  return (
    <>
      <Breadcrumbs
        variant="list"
        elements={[
          { label: t_i18n('Dashboards') },
          { label: t_i18n('Public dashboards'), current: true },
        ]}
      />

      {queryRef && (
        <DataTable
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
            setNumberOfElements: helpers.handleSetNumberOfElements,
          }}
          lineFragment={publicDashboardFragment}
          exportContext={{ entity_type: 'PublicDashboard' }}
          searchContextFinal={{ entityTypes: ['PublicDashboard'] }}
          additionalHeaderButtons={[
            <ToggleButton key="cards" value="lines" aria-label="lines">
              <Tooltip title={t_i18n('Lines view')}>
                <ViewListOutlined color="primary" fontSize="small"/>
              </Tooltip>
            </ToggleButton>,
          ]}
          actions={(row) => {
            console.log('row', row);
            return (
              <>
                <IconButton onClick={(event) => handleOpen(event, row.uri_key)} aria-haspopup="true" size="large" color="primary">
                  <MoreVert/>
                </IconButton>
                <Menu key={row.uri_key} anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
                  <MenuItem aria-label="Go to dashboard">{t_i18n('Go to Original dashboard')}</MenuItem>
                  <MenuItem onClick={() => copyLinkUrl(selectedUriKey)} aria-label="Copy link">{t_i18n('Copy public link')}</MenuItem>
                  <MenuItem aria-label="Disable link">{t_i18n('Disable public link')}</MenuItem>
                </Menu>
              </>
            );
          }
          }
        />
      )}
    </>
  );
};

export default PublicDashboards;
