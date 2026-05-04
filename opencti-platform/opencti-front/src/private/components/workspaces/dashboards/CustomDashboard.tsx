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
import Security from 'src/utils/Security';
import { CustomDashboard_workspace$key } from './__generated__/CustomDashboard_workspace.graphql';
import { CustomDashboardWidgetExportQuery$data } from './__generated__/CustomDashboardWidgetExportQuery.graphql';
import { WIDGET_WORKSPACE_CONTEXT } from './custom-dashboards-utils';

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

const onExportWidget = async (id: string, widget: { id: string; type: string }) => {
  const data = await fetchQuery(dashboardExportWidgetQuery, { id, widgetId: widget.id })
    .toPromise() as CustomDashboardWidgetExportQuery$data;
  if (!data.workspace) {
    MESSAGING$.notifyError('Failed to export widget');
    return null;
  }
  return data.workspace.toWidgetExport;
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

  const helpers = useDashboard({ entity: workspace, onSave, onImportWidget, onExportWidget });
  const { handleAddWidget, handleImportWidget, handleDateChange, config } = helpers;
  return (
    <Stack gap={2}>
      {!noToolbar && (
        <Stack gap={1}>
          <WorkspaceHeader
            handleAddWidget={handleAddWidget}
            handleImportWidget={handleImportWidget}
            data={workspace}
            variant="dashboard"
          />
          <Security
            needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
            hasAccess={userCanEdit}
          >
            <DashboardTimeFilters
              config={config}
              handleDateChange={handleDateChange}
            />
          </Security>
        </Stack>
      )
      }
      <DashboardContent
        helpers={helpers}
        isEditable={userCanEdit}
        entity={workspace}
        context={WIDGET_WORKSPACE_CONTEXT}
      />
    </Stack>
  );
};

export default CustomDashboard;
