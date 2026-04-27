import { graphql, useFragment } from 'react-relay';
import Stack from '@mui/material/Stack';
import DashboardTimeFilters from '../../../../components/dashboard/DashboardTimeFilters';
import WorkspaceHeader from '../workspaceHeader/WorkspaceHeader';
import { commitMutation, handleError, fetchQuery } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import useGranted, { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DashboardContent from '../../../../components/dashboard/DashboardContent';
import useDashboard from '../../../../components/dashboard/useDashboard';

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

const onExportWidget = async (id, widget) => {
  const data = await fetchQuery(dashboardExportWidgetQuery, { id, widgetId: widget.id })
    .toPromise();
  return data.workspace?.toWidgetExport;
};

const CustomDashboard = ({ data, noToolbar = false }) => {
  const workspace = useFragment(dashboardFragment, data);
  const [commitWidgetImportMutation] = useApiMutation(dashboardImportWidgetMutation);

  const userHasEditAccess = workspace.currentUserAccessRight === 'admin'
    || workspace.currentUserAccessRight === 'edit';
  const userHasUpdateCapa = useGranted([EXPLORE_EXUPDATE]);
  const userCanEdit = userHasEditAccess && userHasUpdateCapa;

  const onSave = (id, newManifestEncoded, noRefresh, onCompleted) => {
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
    });
  };

  const onImportWidget = (id, widgetConfig, manifestEncoded) => {
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
          <DashboardTimeFilters
            currentUserAccessRight={workspace.currentUserAccessRight}
            config={config}
            handleDateChange={handleDateChange}
          />
        </Stack>
      )
      }
      <DashboardContent
        helpers={helpers}
        isEditable={userCanEdit}
        dashboardEntity={workspace}
      />
    </Stack>
  );
};

export default CustomDashboard;
