import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import AccessesMenu from '@components/settings/AccessesMenu';
import React, { useEffect, useState } from 'react';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import AuthProviderLogsDrawer from '@components/settings/sso_definitions/AuthProviderLogsDrawer';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';
import type {
  SSODefinitionsLinesPaginationQuery as SSODefinitionsLinesPaginationQueryType,
  SSODefinitionsLinesPaginationQuery$variables,
} from './__generated__/SSODefinitionsLinesPaginationQuery.graphql';
import { SSODefinitionsLinesPaginationQuery } from './__generated__/SSODefinitionsLinesPaginationQuery.graphql';
import { SSODefinitionsLines_data$data } from './__generated__/SSODefinitionsLines_data.graphql';
import type { SSODefinitionsPolling_data$data } from './__generated__/SSODefinitionsPolling_data.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import SSODefinitionCreation from '@components/settings/sso_definitions/SSODefinitionCreation';
import Box from '@mui/material/Box';
import ItemBoolean from '../../../../components/ItemBoolean';
import SSOSingletonStrategies from '@components/settings/sso_definitions/SSOSingletonStrategies';
import AuthenticationGlobalSettings from '@components/settings/sso_definitions/AuthenticationGlobalSettings';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EditOutlined from '@mui/icons-material/EditOutlined';
import ListOutlined from '@mui/icons-material/ListOutlined';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import SSODefinitionEdition from '@components/settings/sso_definitions/SSODefinitionEdition';
import { SSODefinitionEditionFragment$data, SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import Typography from '@mui/material/Typography';

const LOCAL_STORAGE_KEY = 'SSODefinitions';

export const ssoDefinitionsLinesQuery = graphql`
  query SSODefinitionsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: AuthenticationProviderOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SSODefinitionsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
    ...SSODefinitionsPolling_data
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

const ssoDefinitionsLineFragment = graphql`
  fragment SSODefinitionsLine_node on AuthenticationProvider {
    id
    entity_type
    name
    description
    enabled
    runtime_status
    button_label_override
    identifier_override
    type
    ...SSODefinitionEditionFragment
  }
`;
const ssoDefinitionsLinesFragment = graphql`
  fragment SSODefinitionsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
        type: "AuthenticationProviderOrdering"
        defaultValue: name
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "AuthenticationProvidersLinesRefetchQuery") {
    authenticationProviders(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_authenticationProviders") {
      edges {
        node {
          id
          entity_type
          ...SSODefinitionsLine_node
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

const ssoDefinitionsPollingFragment = graphql`
  fragment SSODefinitionsPolling_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "AuthenticationProviderOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  ) {
    authenticationProviders(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          runtime_status
        }
      }
    }
  }
`;

interface EditingSSO {
  data: SSODefinitionEditionFragment$key;
}

const POLL_INTERVAL_FAST_MS = 1000;
const POLL_INTERVAL_SLOW_MS = 60_000;
const POST_UPDATE_WINDOW_MS = 5000;

type SSODefinitionsPollingProps = {
  queryRef: PreloadedQuery<SSODefinitionsLinesPaginationQueryType>;
  loadQuery: (variables: SSODefinitionsLinesPaginationQuery$variables, opts?: { fetchPolicy?: 'store-and-network' }) => void;
  queryPaginationOptions: SSODefinitionsLinesPaginationQuery$variables;
  lastProviderUpdateAt: number | null;
  onRefreshQuery: () => void;
};

const SSODefinitionsPolling = ({ queryRef, loadQuery, queryPaginationOptions, lastProviderUpdateAt, onRefreshQuery }: SSODefinitionsPollingProps) => {
  const queryData = usePreloadedQuery(ssoDefinitionsLinesQuery, queryRef);
  const pollingData = useFragment(ssoDefinitionsPollingFragment, queryData) as SSODefinitionsPolling_data$data | null;
  const edges = pollingData?.authenticationProviders?.edges ?? [];
  const hasAnyStarting = edges.some(
    (e: { node: { runtime_status: string } }) => {
      const status = e?.node?.runtime_status;
      return status === 'STARTING' || status === 'INITIALIZING';
    },
  );
  const lastSlowFetchRef = React.useRef(0);

  useEffect(() => {
    const id = setInterval(() => {
      const now = Date.now();
      const inPostUpdateWindow = lastProviderUpdateAt != null && now - lastProviderUpdateAt < POST_UPDATE_WINDOW_MS;
      const shouldFetchFast = inPostUpdateWindow || hasAnyStarting;
      if (shouldFetchFast) {
        lastSlowFetchRef.current = 0;
        onRefreshQuery();
        loadQuery(queryPaginationOptions, { fetchPolicy: 'store-and-network' });
      } else if (lastSlowFetchRef.current === 0 || now - lastSlowFetchRef.current >= POLL_INTERVAL_SLOW_MS) {
        lastSlowFetchRef.current = now;
        onRefreshQuery();
        loadQuery(queryPaginationOptions, { fetchPolicy: 'store-and-network' });
      }
    }, POLL_INTERVAL_FAST_MS);
    return () => clearInterval(id);
  }, [loadQuery, hasAnyStarting, lastProviderUpdateAt, queryPaginationOptions, onRefreshQuery]);
  return null;
};

const SSODefinitions = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Authentication | Security | Settings'));

  const [editingSSO, setEditingSSO] = useState<EditingSSO | null>(null);
  const [logsDrawerProviderId, setLogsDrawerProviderId] = useState<string | null>(null);
  const [lastProviderUpdateAt, setLastProviderUpdateAt] = useState<number | null>(null);
  const [providerIdsShowingAsStarting, setProviderIdsShowingAsStarting] = useState<Set<string>>(new Set());
  const { settings } = useAuth();

  const handleProviderUpdated = React.useCallback((providerId: string) => {
    setLastProviderUpdateAt(Date.now());
    setProviderIdsShowingAsStarting((prev) => new Set(prev).add(providerId));
  }, []);

  const clearProviderIdsShowingAsStarting = React.useCallback(() => {
    setProviderIdsShowingAsStarting(new Set());
  }, []);

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    filters: emptyFilterGroup,
  };
  const { viewStorage: { filters }, helpers, paginationOptions } = usePaginationLocalStorage<SSODefinitionsLinesPaginationQuery>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const contextFilters = useBuildEntityTypeBasedFilterContext('AuthenticationProvider', filters);
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters };

  const handleOpenEdition = (node: SSODefinitionEditionFragment$key) => {
    setEditingSSO({ data: node });
  };

  const handleOpenLogs = (e: React.MouseEvent, node: { id: string }) => {
    e.stopPropagation();
    setLogsDrawerProviderId(node.id);
  };

  const dataColumns = {
    name: {
      label: t_i18n('Configuration name'),
      percentWidth: 45,
      isSortable: true,
      render: (node: { name: string }) => <div>{node.name}</div>,
    },
    type: {
      label: t_i18n('Authentication strategy'),
      percentWidth: 40,
      isSortable: false,
      render: (node: { type: string }) => {
        const strategyLabel = node.type === 'LDAP' ? t_i18n('FORM') : t_i18n('SSO');
        return <div>{`${node.type} (${strategyLabel})`}</div>;
      },
    },
    enabled: {
      label: t_i18n('Status'),
      percentWidth: 15,
      isSortable: true,
      render: (node: { id: string; runtime_status: 'ACTIVE' | 'DISABLED' | 'ERROR' | 'STARTING'; enabled: boolean }) => {
        const status = providerIdsShowingAsStarting.has(node.id) ? 'STARTING' : node.runtime_status;
        return (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ItemBoolean
              label={
                status === 'ACTIVE'
                  ? t_i18n('Active')
                  : status === 'STARTING'
                    ? t_i18n('Starting')
                    : status === 'ERROR'
                      ? t_i18n('Error')
                      : t_i18n('Disabled')
              }
              status={
                status === 'ACTIVE'
                  ? true
                  : status === 'ERROR'
                    ? 'error'
                    : status === 'DISABLED'
                      ? 'disabled'
                      : undefined
              }
              tooltip={
                status === 'ERROR'
                  ? t_i18n('Provider is enabled but failed to start. Check configuration or logs.')
                  : undefined
              }
            />
            {!isEnterpriseEdition && <span onClick={(e) => e.stopPropagation()}><EEChip /></span>}
          </Box>
        );
      },
    },
  };

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<SSODefinitionsLinesPaginationQueryType>(
    ssoDefinitionsLinesQuery,
    queryPaginationOptions as unknown as SSODefinitionsLinesPaginationQuery$variables,
  );

  const preloadedPaginationProps = {
    linesQuery: ssoDefinitionsLinesQuery,
    linesFragment: ssoDefinitionsLinesFragment,
    queryRef,
    nodePath: ['authenticationProviders', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<SSODefinitionsLinesPaginationQuery>;

  return (
    <div style={{ paddingRight: '200px' }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Settings') },
        { label: t_i18n('Security') },
        { label: t_i18n('Authentications'), current: true }]}
      />
      <AccessesMenu />
      {settings.is_authentication_by_env && (
        <Alert severity="error" variant="outlined" sx={{ mt: 2 }}>
          <AlertTitle>{t_i18n('Deprecated — Authentication management is disabled by environment configuration')}</AlertTitle>
          <Typography variant="body1" sx={{ mb: 2 }}>
            {t_i18n('Your platform is running with the legacy authentication configuration defined through environment variables. This safeguard was enabled in your configuration because the authentication migration to the new v7 model encountered issues that needed to be resolved first.')}
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            <strong>{t_i18n('This compatibility mode is deprecated and will be permanently removed in the next major version of OpenCTI.')}</strong>{' '}
            {t_i18n('Once removed, the platform will no longer be able to start with this configuration, and authentication providers will have to be properly migrated.')}
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            {t_i18n('While this safeguard is active, authentication providers cannot be managed from this interface. The platform continues to operate with the previous environment-based implementation.')}
          </Typography>
          <Typography variant="body1">
            {t_i18n('To resolve this situation before the next version, please')}{' '}
            <a href="https://filigran.io/contact/" target="_blank" rel="noreferrer">{t_i18n('contact the Filigran team')}</a>{' '}
            {t_i18n('so they can assist you with the migration process.')}
          </Typography>
        </Alert>
      )}
      {!settings.is_authentication_by_env && (
        <>
          <AuthenticationGlobalSettings />
          <SSOSingletonStrategies />
          {queryRef && (
            <>
              <SSODefinitionsPolling
                queryRef={queryRef as PreloadedQuery<SSODefinitionsLinesPaginationQueryType>}
                loadQuery={loadQuery as (vars: SSODefinitionsLinesPaginationQuery$variables, opts?: { fetchPolicy?: 'store-and-network' }) => void}
                queryPaginationOptions={queryPaginationOptions as unknown as SSODefinitionsLinesPaginationQuery$variables}
                lastProviderUpdateAt={lastProviderUpdateAt}
                onRefreshQuery={clearProviderIdsShowingAsStarting}
              />
              <DataTable
                dataColumns={dataColumns}
                resolvePath={(data: SSODefinitionsLines_data$data) => data.authenticationProviders?.edges?.map((e) => e?.node)}
                storageKey={LOCAL_STORAGE_KEY}
                initialValues={initialValues}
                contextFilters={contextFilters}
                lineFragment={ssoDefinitionsLineFragment}
                preloadedPaginationProps={preloadedPaginationProps}
                entityTypes={['AuthenticationProvider']}
                searchContextFinal={{ entityTypes: ['AuthenticationProvider'] }}
                disableToolBar
                disableColumnMenu
                removeSelectAll
                disableLineSelection
                disableNavigation
                onLineClick={handleOpenEdition}
                actionsColumnWidth={72}
                actions={(node: SSODefinitionEditionFragment$data) => (
                  <>
                    <Tooltip title={t_i18n('Update')}>
                      <IconButton size="small" aria-label={t_i18n('Update')}>
                        <EditOutlined fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title={t_i18n('Logs')}>
                      <IconButton
                        size="small"
                        onClick={(e) => handleOpenLogs(e, node)}
                        aria-label={t_i18n('Logs')}
                      >
                        <ListOutlined fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </>
                )}
                createButton={<SSODefinitionCreation paginationOptions={queryPaginationOptions} />}
              />
            </>
          )}
          {editingSSO && (
            <SSODefinitionEdition
              isOpen={!!editingSSO}
              onClose={() => setEditingSSO(null)}
              data={editingSSO.data}
              paginationOptions={queryPaginationOptions}
              onProviderUpdated={handleProviderUpdated}
            />
          )}
          {logsDrawerProviderId && (
            <AuthProviderLogsDrawer
              isOpen={!!logsDrawerProviderId}
              onClose={() => setLogsDrawerProviderId(null)}
              providerId={logsDrawerProviderId}
            />
          )}
        </>
      )}
    </div>
  );
};

export default SSODefinitions;
