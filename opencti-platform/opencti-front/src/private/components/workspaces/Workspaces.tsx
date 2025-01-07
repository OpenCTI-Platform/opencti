import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { WorkspacesLinesPaginationQuery, WorkspacesLinesPaginationQuery$variables } from '@components/workspaces/__generated__/WorkspacesLinesPaginationQuery.graphql';
import { WorkspacesLines_data$data } from '@components/workspaces/__generated__/WorkspacesLines_data.graphql';
import WorkspacePopover from '@components/workspaces/WorkspacePopover';
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
import { textInTooltip } from '../../../components/dataGrid/dataTableUtils';

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
      render: ({ name }, h) => textInTooltip(name, h),
    },
    tags: {
      id: 'tags',
    },
    creator: {
      id: 'creator',
      isSortable: true,
      render: ({ owner }, h) => textInTooltip(owner.name, h),
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
          createButton={isFeatureEnable('FAB_REPLACEMENT') && (
            <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}>
              <WorkspaceCreation
                paginationOptions={workspacePaginationOptions}
                type={type}
              />
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

      {!FAB_REPLACED
        && (<Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}>
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
