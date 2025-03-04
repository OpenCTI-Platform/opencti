import React, { FunctionComponent, useContext } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { WorkspacesLinesPaginationQuery, WorkspacesLinesPaginationQuery$variables } from '@components/workspaces/__generated__/WorkspacesLinesPaginationQuery.graphql';
import { WorkspacesLines_data$data } from '@components/workspaces/__generated__/WorkspacesLines_data.graphql';
import WorkspacePopover from '@components/workspaces/WorkspacePopover';
import { useTheme } from '@mui/styles';
import WorkspaceCreation from './WorkspaceCreation';
import Security from '../../../utils/Security';
import { EXPLORE, EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import GradientButton from '../../../components/GradientButton';
import type { Theme } from '../../../components/Theme';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../utils/utils';

const workspaceLineFragment = graphql`
  fragment WorkspacesLine_node on Workspace {
    id
    name
    tags
    created_at
    updated_at
    type
    manifest
    isShared
    entity_type
    owner {
      id
      name
      entity_type
    }
    currentUserAccessRight
  }
`;

const workspacesLinesQuery = graphql`
  query WorkspacesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: WorkspacesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...WorkspacesLines_data
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

const workspacesLineFragment = graphql`
  fragment WorkspacesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "WorkspacesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "WorkspacesLinesRefetchQuery") {
    workspaces(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_workspaces") {
      edges {
        node {
          id
          ...WorkspacesLine_node
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
interface WorkspacesProps {
  type: string;
}

const Workspaces: FunctionComponent<WorkspacesProps> = ({
  type,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FAB_REPLACED = isFeatureEnable('FAB_REPLACEMENT');
  const isXTMHubFeatureEnabled = isFeatureEnable('XTM_HUB_INTEGRATION');

  const theme = useTheme<Theme>();
  const { settings } = useContext(UserContext);
  const importFromHubUrl = isNotEmptyField(settings) ? `${settings.platform_xtmhub_url}/redirect/custom_dashboards?octi_instance_id=${settings.id}` : '';

  const { setTitle } = useConnectedDocumentModifier();
  setTitle(type === 'dashboard' ? t_i18n('Custom dashboards | Dashboards') : t_i18n('Investigations'));

  const LOCAL_STORAGE_KEY = `view-${type}-list`;
  const initialStorageValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
    filters: emptyFilterGroup,
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<WorkspacesLinesPaginationQuery$variables>(
    `view-${type}-list`,
    initialStorageValues,
  );

  const filters = useBuildEntityTypeBasedFilterContext(
    'Workspace',
    {
      mode: 'and',
      filters: [{
        key: 'type',
        values: [type],
        mode: 'or',
        operator: 'eq',
      }],
      filterGroups: viewStorage.filters ? [viewStorage.filters] : [],
    },
  );

  const workspacePaginationOptions = {
    ...paginationOptions,
    filters,
  } as unknown as WorkspacesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<WorkspacesLinesPaginationQuery>(
    workspacesLinesQuery,
    workspacePaginationOptions,
  );

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      percentWidth: 33,
    },
    tags: {
      id: 'tags',
    },
    creator: {
      id: 'creator',
      isSortable: true,
      render: ({ owner }) => defaultRender(owner.name),
    },
    created_at: {
      id: 'created_at',
      percentWidth: 16,
    },
    updated_at: {
      id: 'updated_at',
      percentWidth: type === 'dashboard' ? 16 : 24,
    },
    ...(type === 'dashboard' ? {
      isShared: {
        id: 'isShared',
      },
    } : {}),
  };

  return (
    <>
      <Breadcrumbs
        elements={type === 'dashboard'
          ? [{ label: t_i18n('Dashboards') }, { label: t_i18n('Custom dashboards'), current: true }]
          : [{ label: t_i18n('Investigations'), current: true }]
        }
      />

      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: WorkspacesLines_data$data) => {
            return data.workspaces?.edges?.map((n) => n?.node);
          }}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialStorageValues}
          toolbarFilters={filters}
          preloadedPaginationProps={{
            linesQuery: workspacesLinesQuery,
            linesFragment: workspacesLineFragment,
            queryRef,
            nodePath: ['workspaces', 'pageInfo', 'globalCount'],
            setNumberOfElements: storageHelpers.handleSetNumberOfElements,
          }}
          lineFragment={workspaceLineFragment}
          entityTypes={['Workspace']}
          searchContextFinal={{ entityTypes: ['Workspace'] }}
          createButton={isFeatureEnable('FAB_REPLACEMENT') ? (
            <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}>
              <WorkspaceCreation
                paginationOptions={workspacePaginationOptions}
                type={type}
              />
            </Security>
          ) : isXTMHubFeatureEnabled && isNotEmptyField(importFromHubUrl) && (
            <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}>
              <GradientButton
                color='primary'
                variant='outlined'
                size="small"
                disableElevation
                sx={{ marginLeft: theme.spacing(1) }}
                href={importFromHubUrl}
                target="_blank"
                title={t_i18n('Import from Hub')}
              >
                {t_i18n('Import from Hub')}
              </GradientButton>
            </Security>
          )}
          taskScope={type === 'dashboard' ? 'DASHBOARD' : 'INVESTIGATION'}
          actions={(row) => (
            <Security needs={row.type === 'dashboard' ? [EXPLORE] : [INVESTIGATION_INUPDATE]}>
              <WorkspacePopover
                workspace={row}
                paginationOptions={workspacePaginationOptions}
              />
            </Security>
          )}
        />
      )}

      {!FAB_REPLACED && (
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}>
          <WorkspaceCreation
            paginationOptions={workspacePaginationOptions}
            type={type}
          />
        </Security>
      )}
    </>
  );
};

export default Workspaces;
