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
import { getDashboardExportHandler } from '../../../../components/dashboard/import-export/dashboard-export-utils';
import Security from 'src/utils/Security';
import { CustomDashboard_workspace$key } from './__generated__/CustomDashboard_workspace.graphql';
import { CustomDashboardWidgetExportQuery$data } from './__generated__/CustomDashboardWidgetExportQuery.graphql';
import { WIDGET_WORKSPACE_HOST } from './custom-dashboards-utils';
import { CustomDashboardExportQuery$data } from './__generated__/CustomDashboardExportQuery.graphql';
import { useEffect, useState } from 'react';
import { Box } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';

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
    refresh_rate
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
  const { t_i18n } = useFormatter();
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

  const refreshRate = workspace.refresh_rate ? workspace.refresh_rate * 1000 : null;
  const [lastRefreshTime, setLastRefreshTime] = useState(new Date());
  const [timeAgoText, setTimeAgoText] = useState('');

  const formatTimeAgo = (date: Date): string => {
    const diffMin = Math.floor((Date.now() - date.getTime()) / 60000);
    if (diffMin === 0) return t_i18n('Just now');
    if (diffMin < 60) return `${diffMin} ${t_i18n('min ago')}`;
    const diffHours = Math.floor(diffMin / 60);
    return `${diffHours} ${t_i18n('hour(s) ago')}`;
  };

  useEffect(() => {
    setTimeAgoText(formatTimeAgo(lastRefreshTime));
    const interval = setInterval(() => {
      setTimeAgoText(formatTimeAgo(lastRefreshTime));
    }, 60000);
    return () => clearInterval(interval);
  }, [lastRefreshTime]);

  useEffect(() => {
    if (!refreshRate) return;
    const interval = setInterval(() => {
      setLastRefreshTime(new Date());
    }, refreshRate);
    return () => clearInterval(interval);
  }, [refreshRate]);

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
        {!noToolbar && (
          <Security
            needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
            hasAccess={userCanEdit}
          >
            <div style={{ marginBottom: 12 }}>
              <DashboardTimeFilters
                config={config}
                handleDateChange={handleDateChange}
              />
            </div>
          </Security>
        )
      }
      <DashboardContent
        helpers={helpers}
        isEditable={userCanEdit}
        entity={workspace}
        host={WIDGET_WORKSPACE_HOST}
        refreshRate={refreshRate}
      /></div>
    </Stack>
  );
};

export default CustomDashboard;
