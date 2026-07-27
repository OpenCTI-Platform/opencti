import { graphql, useFragment } from 'react-relay';
import Stack from '@mui/material/Stack';
import DashboardTimeFilters from '../../../../components/dashboard/DashboardTimeFilters';
import WorkspaceHeader from '../workspaceHeader/WorkspaceHeader';
import { commitMutation, handleError, fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import useGranted, { EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DashboardContent from '../../../../components/dashboard/DashboardContent';
import useDashboard from '../../../../components/dashboard/useDashboard';
import useDashboardRefresh from '../../../../components/dashboard/useDashboardRefresh';
import { getDashboardExportHandler } from '../../../../components/dashboard/import-export/dashboard-export-utils';
import DashboardRefreshControl from '../../../../components/dashboard/DashboardRefreshControl';
import { DashboardRefreshProvider } from '../../../../components/dashboard/DashboardRefreshContext';
import Security from 'src/utils/Security';
import { CustomDashboard_workspace$key } from './__generated__/CustomDashboard_workspace.graphql';
import { CustomDashboardWidgetExportQuery$data } from './__generated__/CustomDashboardWidgetExportQuery.graphql';
import { WIDGET_WORKSPACE_HOST } from './custom-dashboards-utils';
import { CustomDashboardExportQuery$data } from './__generated__/CustomDashboardExportQuery.graphql';
import { Box } from '@mui/material';

const dashboardExportWidgetQuery = graphql`
  query CustomDashboardWidgetExportQuery($id: String!, $widgetId: ID!) {
    workspace(id: $id) {
      toWidgetExport(widgetId: $widgetId)
    }
  }
`;

const dashboardLayoutMutation = graphql`
  mutation CustomDashboardLayoutMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const dashboardImportWidgetMutation = graphql`
  mutation CustomDashboardWidgetImportMutation(
    $id: ID!
    $input: ImportConfigurationInput!
  ) {
    workspaceWidgetConfigurationImport(id: $id, input: $input) {
      ...CustomDashboard_workspace
    }
  }
`;

const dashboardFragment = graphql`
  fragment CustomDashboard_workspace on Workspace {
    id
    type
    name
    description
    manifest
    refresh_interval
    tags
    owner {
      id
      name
      entity_type
    }
    currentUserAccessRight
    ...WorkspaceEditionContainer_workspace
    ...WorkspaceHeaderFragment
  }
`;

const dashboardExportQuery = graphql`
    query CustomDashboardExportQuery($id: String!) {
        workspace(id: $id) {
            toConfigurationExport
        }
    }
`;

const onExportWidget = async (id: string, widget: { id: string; type: string }) => {
  const data = await fetchQuery(dashboardExportWidgetQuery, { id, widgetId: widget.id })
    .toPromise() as CustomDashboardWidgetExportQuery$data;
  if (!data.workspace) {
    MESSAGING$.notifyError('Failed to export widget');
    return null;
  }
  return data.workspace.toWidgetExport;
};

const onExport = async (id: string) => {
  const data = await fetchQuery(dashboardExportQuery, { id })
    .toPromise() as CustomDashboardExportQuery$data;
  if (!data.workspace) {
    return null;
  }
  return data.workspace.toConfigurationExport;
};

interface CustomDashboardProps {
  data: CustomDashboard_workspace$key;
  noToolbar?: boolean;
}

const CustomDashboard = ({ data, noToolbar = false }: CustomDashboardProps) => {
  const workspace = useFragment(dashboardFragment, data);
  const [commitWidgetImportMutation] = useApiMutation(dashboardImportWidgetMutation);

  const userHasEditAccess = workspace.currentUserAccessRight === 'admin'
    || workspace.currentUserAccessRight === 'edit';
  const userHasUpdateCapa = useGranted([EXPLORE_EXUPDATE]);
  const userCanEdit = userHasEditAccess && userHasUpdateCapa;

  const onSave = (id: string, newManifestEncoded: string, noRefresh: boolean, onCompleted: () => void) => {
    const mutation = noRefresh ? dashboardLayoutMutation : workspaceMutationFieldPatch;
    commitMutation({
      mutation,
      variables: {
        id,
        input: {
          key: 'manifest',
          value: newManifestEncoded,
        },
      },
      onCompleted,
      // Remove these once commitMutation gets migrated to TS
      onError: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      setSubmitting: undefined,
      updater: undefined,
    });
  };

  const onImportWidget = (id: string, widgetConfig: File, manifestEncoded: string) => {
    commitWidgetImportMutation({
      variables: {
        id,
        input: {
          importType: 'widget',
          file: widgetConfig,
          dashboardManifest: manifestEncoded,
        },
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const helpers = useDashboard({
    entity: workspace,
    onSave,
    onImportWidget,
    onExportWidget,
  });
  const { handleAddWidget, handleImportWidget, handleDateChange, config } = helpers;
  const handleExport = getDashboardExportHandler({ onExport, configType: 'dashboard', entity: workspace });

  const {
    localRefreshRateSeconds,
    refreshRate,
    refreshToken,
    isAutoRefreshing,
    handleManualRefresh,
    handleRefreshRateChange,
  } = useDashboardRefresh({
    initialRefreshRateSeconds: workspace.refresh_interval ?? 0,
    onRefreshRateChange: (refreshRateInSeconds: number) => {
      commitMutation({
        mutation: workspaceMutationFieldPatch,
        variables: {
          id: workspace.id,
          input: {
            key: 'refresh_interval',
            value: refreshRateInSeconds,
          },
        },
        // Remove these once commitMutation gets migrated to TS
        onCompleted: undefined,
        onError: undefined,
        optimisticResponse: undefined,
        optimisticUpdater: undefined,
        setSubmitting: undefined,
        updater: undefined,
      });
    },
  });

  return (
    <Stack gap={2}>
      {!noToolbar && (
        <Stack gap={1}>
          <WorkspaceHeader
            handleAddWidget={handleAddWidget}
            handleImportWidget={handleImportWidget}
            handleExport={handleExport}
            data={workspace}
            variant="dashboard"
          />
        </Stack>
      )
      }
      <div id="container">
        <DashboardRefreshProvider refreshToken={refreshToken}>
          {!noToolbar && (
            <Security
              needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
              hasAccess={userCanEdit}
            >
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 1.5,
                }}
              >
                <DashboardTimeFilters
                  config={config}
                  handleDateChange={handleDateChange}
                />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <DashboardRefreshControl
                    onRefresh={handleManualRefresh}
                    interval={localRefreshRateSeconds}
                    onIntervalChange={handleRefreshRateChange}
                    isRefreshing={isAutoRefreshing}
                  />
                </Box>
              </Box>
            </Security>
          )
          }
          <DashboardContent
            helpers={helpers}
            isEditable={userCanEdit}
            entity={workspace}
            host={WIDGET_WORKSPACE_HOST}
            refreshRate={refreshRate}
          />
        </DashboardRefreshProvider>
      </div>
    </Stack>
  );
};

export default CustomDashboard;
