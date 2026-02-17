import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import AccessesMenu from '@components/settings/AccessesMenu';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import AuthProviderLogsDrawer from '@components/settings/sso_definitions/AuthProviderLogsDrawer';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import DataTable from '../../../../components/dataGrid/DataTable';
import { SSODefinitionsLinesPaginationQuery } from './__generated__/SSODefinitionsLinesPaginationQuery.graphql';
import { SSODefinitionsLines_data$data } from './__generated__/SSODefinitionsLines_data.graphql';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import SSODefinitionCreation from '@components/settings/sso_definitions/SSODefinitionCreation';
import Box from '@mui/material/Box';
import ItemBoolean from '../../../../components/ItemBoolean';
import AuthenticationDefinitionAlert from '@components/settings/sso_definitions/AuthenticationDefinitionAlert';
import SSOSingletonStrategies from '@components/settings/sso_definitions/SSOSingletonStrategies';
import AuthenticationGlobalSettings from '@components/settings/sso_definitions/AuthenticationGlobalSettings';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import EEChip from '@components/common/entreprise_edition/EEChip';
import EditOutlined from '@mui/icons-material/EditOutlined';
import ListOutlined from '@mui/icons-material/ListOutlined';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import SSODefinitionEdition from '@components/settings/sso_definitions/SSODefinitionEdition';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';

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
  }
`;

const ssoDefinitionsLineFragment = graphql`
  fragment SSODefinitionsLine_node on AuthenticationProvider {
    id
    entity_type
    name
    description
    enabled
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
    authenticationProviderSettings {
      is_force_env
    }
  }
`;

interface EditingSSO {
  data: SSODefinitionEditionFragment$key;
}

const SSODefinitions = () => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Authentication | Security | Settings'));

  const [editingSSO, setEditingSSO] = useState<EditingSSO | null>(null);
  const [logsDrawerProviderId, setLogsDrawerProviderId] = useState<string | null>(null);

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
      render: (node: { type: string }) => <div>{node.type}</div>,
    },
    enabled: {
      label: ' ',
      percentWidth: 15,
      isSortable: true,
      render: (node: { enabled: boolean }) => (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ItemBoolean
            label={node.enabled && isEnterpriseEdition ? t_i18n('Enabled') : t_i18n('Disabled')}
            status={node.enabled && isEnterpriseEdition}
          />
          {!isEnterpriseEdition && <span onClick={(e) => e.stopPropagation()}><EEChip /></span>}
        </Box>
      ),
    },
  };

  const queryRef = useQueryLoading(
    ssoDefinitionsLinesQuery,
    queryPaginationOptions,
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
      <>
        <AuthenticationGlobalSettings />
        <SSOSingletonStrategies />
        {queryRef && (
          <>
            <AuthenticationDefinitionAlert preloadedPaginationProps={preloadedPaginationProps} />
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
              actions={(node: SSODefinitionEditionFragment$key) => (
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
    </div>
  );
};

export default SSODefinitions;
