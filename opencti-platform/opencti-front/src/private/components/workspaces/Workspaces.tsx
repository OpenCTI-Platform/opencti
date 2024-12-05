import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { WorkspacesLinesPaginationQuery, WorkspacesLinesPaginationQuery$variables } from '@components/workspaces/__generated__/WorkspacesLinesPaginationQuery.graphql';
import { WorkspaceLineDummy, workspaceLineFragment } from '@components/workspaces/WorkspaceLine';
import { WorkspacesLines_data$data } from '@components/workspaces/__generated__/WorkspacesLines_data.graphql';
import WorkspacePopover from '@components/workspaces/WorkspacePopover';
import ListLines from '../../../components/list_lines/ListLines';
import WorkspacesLines, { workspacesLineFragment, workspacesLinesQuery } from './WorkspacesLines';
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

  const {
    numberOfElements,
    searchTerm,
    sortBy,
    orderAsc,
  } = viewStorage;

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

  const renderDataTable = () => {
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

    return queryRef && (
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
    );
  };

  const renderLines = () => {
    const dataColumns = {
      name: {
        label: 'Name',
        width: '30%',
        isSortable: true,
      },
      tags: {
        label: 'Tags',
        width: '20%',
        isSortable: false,
      },
      creator: {
        label: 'Creator',
        width: '10%',
        isSortable: true,
      },
      created_at: {
        label: 'Platform creation date',
        width: '15%',
        isSortable: true,
      },
      updated_at: {
        label: 'Modification date',
        width: '15%',
        isSortable: true,
      },
      ...(type === 'dashboard' ? {
        isShared: {
          id: 'isShared',
          label: 'Shared',
          width: '10%',
          isSortable: false,
        },
      } : {}),
    };

    return (
      <div data-testid="dashboard-page">
        <ListLines
          helpers={storageHelpers}
          sortBy={sortBy}
          orderAsc={orderAsc}
          dataColumns={dataColumns}
          handleSort={storageHelpers.handleSort}
          handleSearch={storageHelpers.handleSearch}
          keyword={searchTerm}
          secondaryAction={true}
          paginationOptions={workspacePaginationOptions}
          numberOfElements={numberOfElements}
          createButton={FAB_REPLACED && <Security needs={[EXPLORE_EXUPDATE]}>
            <WorkspaceCreation
              paginationOptions={workspacePaginationOptions}
              type={type}
            />
          </Security>}
        >
          {queryRef && (
            <React.Suspense
              fallback={
                <>
                  {Array(20)
                    .fill(0)
                    .map((_, idx) => (
                      <WorkspaceLineDummy key={idx} dataColumns={dataColumns} />
                    ))}
                </>
              }
            >
              <WorkspacesLines
                queryRef={queryRef}
                paginationOptions={workspacePaginationOptions}
                dataColumns={dataColumns}
                setNumberOfElements={storageHelpers.handleSetNumberOfElements}
              />
            </React.Suspense>
          )}
        </ListLines>
      </div>
    );
  };

  return (
    <>
      <Breadcrumbs
        elements={type === 'dashboard'
          ? [{ label: t_i18n('Dashboards') }, { label: t_i18n('Custom dashboards'), current: true }]
          : [{ label: t_i18n('Investigations'), current: true }]
        }
      />

      {isFeatureEnable('PUBLIC_DASHBOARD_LIST') ? renderDataTable() : renderLines()}

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
