import React from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewListOutlined } from '@mui/icons-material';
import { workspaceShareListQuery } from '@components/workspaces/WorkspaceShareList';
import { WorkspaceShareListQuery, WorkspaceShareListQuery$data, WorkspaceShareListQuery$variables } from '@components/workspaces/__generated__/WorkspaceShareListQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import DataTable from '../../../../components/dataGrid/DataTable';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY = 'public_dashboards';
// const publicDashboardsQuery = graphql`
//   query PublicDashboard{
//     publicDashboards {
//       edges {
//         node {
//           id
//           name
//           enabled
//         }
//       }
//     }
// }`;
// console.log('publicDashboards', publicDashboardsQuery);
const PublicDashboardComponent = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<WorkspaceShareListQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('Public dashboards', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };
  const queryRef = useQueryLoading<WorkspaceShareListQuery>(
    workspaceShareListQuery,
  );
  const renderList = () => {
    const dataColumns = {
      name: {
        flexSize: 15,
      },
      publicDashboard_types: {
        flexSize: 10,
      },
      is_family: {},
      created: {},
      modified: {},
      createdBy: {},
      objectMarking: { flexSize: 10 },
      objectLabel: {},
    };
    const preloadedPaginationProps = {
      linesQuery: workspaceShareListQuery,
      linesFragment: workspaceShareListQuery,
      queryRef,
      nodes: ['public_dashboards'],
    } as UsePreloadedPaginationFragment<any>;

    return (
      <>
        <Breadcrumbs variant="list" elements={[{ label: t_i18n('Dashboards') }, { label: t_i18n('Public Dashboards'), current: true }]}/>
        {queryRef && (
          <DataTable
            dataColumns={dataColumns}
            resolvePath={(data: WorkspaceShareListQuery$data) => data.publicDashboards?.edges?.map((n) => n?.node)}
            storageKey={LOCAL_STORAGE_KEY}
            initialValues={initialValues}
            preloadedPaginationProps={preloadedPaginationProps}
            exportContext={{ entity_type: 'PublicDashboards' }}
            lineFragment={workspaceShareListQuery}
            additionalHeaderButtons={[
              <ToggleButton key="cards" value="lines" aria-label="lines">
                <Tooltip title={t_i18n('Lines view')}>
                  <ViewListOutlined color="primary" fontSize="small"/>
                </Tooltip>
              </ToggleButton>,
            ]}
          />
        )}
      </>
    );
  };

  return (
    <>
      {renderList()}
    </>
  );
};

export default PublicDashboardComponent;
