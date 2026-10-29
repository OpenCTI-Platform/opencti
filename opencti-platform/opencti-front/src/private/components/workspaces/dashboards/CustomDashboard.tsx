import { useMemo, useState } from 'react';
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
import { DashboardVariableValuesProvider } from '../../../../components/dashboard/DashboardVariableValuesContext';
import { DashboardVariablesProvider } from '../../../../components/dashboard/DashboardVariablesContext';
import { useDashboardVariables } from '../../../../components/dashboard/useDashboardVariables';
import { useDashboardTimeRange } from '../../../../components/dashboard/useDashboardTimeRange';
import DashboardValuesActions from '../../../../components/dashboard/DashboardValuesActions';
import DashboardViewerPermissions from '../../../../components/dashboard/DashboardViewerPermissions';
import DashboardVariablesBar from '../../../../components/dashboard/variables/DashboardVariablesBar';
import DashboardVariableDialog from '../../../../components/dashboard/variables/DashboardVariableDialog';
import DashboardVariableDeletion from '../../../../components/dashboard/variables/DashboardVariableDeletion';
import type { DashboardVariable } from '../../../../components/dashboard/dashboard-types';
import { useDashboardVariableMutations } from '../../../../components/dashboard/variables/useDashboardVariableMutations';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from '../../../../components/dashboard/dashboardVariablesFeatureFlag';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from 'src/utils/Security';
import { CustomDashboard_workspace$key } from './__generated__/CustomDashboard_workspace.graphql';
import { CustomDashboardWidgetExportQuery$data } from './__generated__/CustomDashboardWidgetExportQuery.graphql';
import { WIDGET_WORKSPACE_HOST } from './custom-dashboards-utils';
import { CustomDashboardExportQuery } from './__generated__/CustomDashboardExportQuery.graphql';
import { Box } from '@mui/material';
import { useFormatter } from 'src/components/i18n';

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
    variables {
      id
      usedInWidgetIds
    }
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
  const { isFeatureEnable } = useHelper();
  const isVariablesEnabled = isFeatureEnable(DASHBOARD_VARIABLES_FEATURE_FLAG);
  const canManageVariables = userCanEdit;
  // undefined: dialog closed, null: creating a variable, a variable: editing it.
  const [dialogVariable, setDialogVariable] = useState<DashboardVariable | null | undefined>(undefined);
  const [variableToDelete, setVariableToDelete] = useState<DashboardVariable | undefined>(undefined);

  const onExportWidget = async (id: string, widget: { id: string; type: string }) => {
    try {
      const data = await fetchQuery(dashboardExportWidgetQuery, { id, widgetId: widget.id })
        .toPromise() as CustomDashboardWidgetExportQuery$data;
      const exportString = data.workspace?.toWidgetExport;
      if (!exportString) {
        MESSAGING$.notifyError(t_i18n('Failed to export widget'));
        return null;
      }
      return exportString;
    } catch (e) {
      MESSAGING$.notifyRelayError(e);
      return null;
    }
  };

  const onExport = async (id: string) => {
    try {
      const data = await fetchQuery<CustomDashboardExportQuery>(dashboardExportQuery, { id })
        .toPromise();
      if (!data?.workspace) {
        return null;
      }
      return data.workspace.toConfigurationExport;
    } catch (e) {
      MESSAGING$.notifyRelayError(e);
      return null;
    }
  };

  const onSave = (id: string, newManifestEncoded: string, noRefresh: boolean, onCompleted: () => void, onError?: (error: Error) => void) => {
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
      onError,
      // Remove these once commitMutation gets migrated to TS
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
  const { handleAddWidget, handleImportWidget, handleDateChange, handleConfigChange, config, variables, widgetsArray } = helpers;
  // The bar is the only way to see, change and clear a per user value: to a user who does not get it, such a
  // value (stored, or from the URL) would filter the widgets with no chip to show or reset it.
  const showVariablesBar = isVariablesEnabled && !noToolbar
    && (canManageVariables || config.allowViewersToChangeVariables === true);
  // The home dashboard (noToolbar) and a user without the bar only ever see the manifest defaults:
  // no per user value is read or written.
  const variableControls = useDashboardVariables(workspace.id, variables, { ignoreLocalValues: noToolbar || !showVariablesBar });
  // Flag on, the time range is per user: an editor always gets the time filters, a reader only when viewers may edit
  // them. As for the variables, a user without them only ever sees the manifest range.
  const showTimeFilters = isVariablesEnabled && !noToolbar
    && (userCanEdit || config.allowViewersToEditTimeFilters === true);
  const timeRange = useDashboardTimeRange(workspace.id, config, { ignoreLocalValues: noToolbar || !showTimeFilters });
  // Mirrors the bar, which renders nothing without variables nor a way to create one.
  const isBarVisible = showVariablesBar && (variables.length > 0 || canManageVariables);
  // Summarized by its signature: the widgets re-resolve their filters whenever this set changes.
  const dateVariableIdsSignature = JSON.stringify(variables.filter((variable) => variable.type === 'date').map((variable) => variable.id));
  const dateVariableIds = useMemo(() => new Set<string>(JSON.parse(dateVariableIdsSignature)), [dateVariableIdsSignature]);
  const { setAsDefaults } = useDashboardVariableMutations(workspace.id);
  const usedInWidgetIdsByVariable = useMemo(
    () => new Map(workspace.variables.map((variable) => [variable.id, [...variable.usedInWidgetIds]])),
    [workspace.variables],
  );
  const onReset = () => {
    variableControls.reset();
    timeRange.reset();
  };
  const onSetAsDefaults = async () => {
    try {
      const submittedValues = variableControls.values;
      const submittedRange = timeRange.range;
      if (timeRange.isModified) {
        await handleConfigChange(submittedRange);
        timeRange.resetRange(submittedRange);
      }
      await setAsDefaults(variables, submittedValues);
      // The server default now is the submitted value: the local entry is redundant, unless it changed since.
      variableControls.resetValues(submittedValues);
    } catch {
      // The mutation already notified the user: this only avoids an unhandled rejection.
      // The local values are kept so nothing the user chose is lost.
    }
  };
  // Definitions offered in the widget filters. CustomDashboard always is the workspace host (WIDGET_WORKSPACE_HOST);
  // the home dashboard (noToolbar) edits no widget. Undefined: filters strictly unchanged.
  const variableDefinitions = isVariablesEnabled && !noToolbar ? variables : undefined;
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

  const refreshControl = (
    <DashboardRefreshControl
      onRefresh={handleManualRefresh}
      interval={localRefreshRateSeconds}
      onIntervalChange={handleRefreshRateChange}
      isRefreshing={isAutoRefreshing}
    />
  );
  // The widgets follow the per user range; flag off, the manifest one, untouched.
  // Memoized: the widgets rebuild their queries when the config identity changes.
  const contentConfig = useMemo(() => ({ ...config, ...timeRange.range }), [config, timeRange.range]);
  const contentHelpers = isVariablesEnabled ? { ...helpers, config: contentConfig } : helpers;

  return (
    // Around the whole page: the Create widget entry point lives in the header.
    <DashboardVariablesProvider variables={variableDefinitions}>
      <Stack sx={{
        gap: 2,
      }}
      >
        {!noToolbar && (
          <Stack sx={{
            gap: 1,
          }}
          >
            <WorkspaceHeader
              handleAddWidget={handleAddWidget}
              handleImportWidget={handleImportWidget}
              handleExport={handleExport}
              data={workspace}
              variant="dashboard"
              editionExtra={isVariablesEnabled ? (
                <DashboardViewerPermissions
                  config={config}
                  // A failure is already notified by the mutation, and the switch follows the saved config.
                  onChange={(patch) => {
                    handleConfigChange(patch).catch(() => {});
                  }}
                />
              ) : undefined}
            />
          </Stack>
        )
        }
        <div id="container">
          <DashboardRefreshProvider refreshToken={refreshToken}>
            {!noToolbar && !isVariablesEnabled && (
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
                    {refreshControl}
                  </Box>
                </Box>
              </Security>
            )}
            {showTimeFilters && (
              <Box
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 1.5,
                }}
              >
                <DashboardTimeFilters
                  config={timeRange.range}
                  handleDateChange={timeRange.setDate}
                />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  {/* Without the bar the actions close this row: only a reader, who never sets the defaults. */}
                  {!isBarVisible && timeRange.isModified && (
                    <DashboardValuesActions canSetAsDefaults={false} onReset={onReset} />
                  )}
                  <Security
                    needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]}
                    hasAccess={userCanEdit}
                  >
                    {refreshControl}
                  </Security>
                </Box>
              </Box>
            )}
            {showVariablesBar && (
              <DashboardVariablesBar
                variables={variables}
                values={variableControls.values}
                defaults={variableControls.defaults}
                usedInWidgetIdsByVariable={usedInWidgetIdsByVariable}
                canManage={canManageVariables}
                isTimeRangeModified={timeRange.isModified}
                onSetValue={variableControls.setValue}
                onReset={onReset}
                onSetAsDefaults={onSetAsDefaults}
                onCreate={canManageVariables ? () => setDialogVariable(null) : undefined}
                onEdit={canManageVariables ? setDialogVariable : undefined}
                onDelete={canManageVariables ? setVariableToDelete : undefined}
              />
            )}
            {showVariablesBar && variableToDelete && (
              <DashboardVariableDeletion
                workspaceId={workspace.id}
                variable={variableToDelete}
                usedInWidgetIds={usedInWidgetIdsByVariable.get(variableToDelete.id) ?? []}
                widgets={widgetsArray}
                onClose={() => setVariableToDelete(undefined)}
              />
            )}
            {showVariablesBar && dialogVariable !== undefined && (
              <DashboardVariableDialog
                open
                workspaceId={workspace.id}
                variable={dialogVariable ?? undefined}
                existingVariables={variables}
                onClose={() => setDialogVariable(undefined)}
              />
            )}
            <DashboardVariableValuesProvider values={variableControls.values} dateVariableIds={dateVariableIds}>
              <DashboardContent
                helpers={contentHelpers}
                usageMarkerVariables={variableDefinitions}
                isEditable={userCanEdit}
                entity={workspace}
                host={WIDGET_WORKSPACE_HOST}
                refreshRate={refreshRate}
              />
            </DashboardVariableValuesProvider>
          </DashboardRefreshProvider>
        </div>
      </Stack>
    </DashboardVariablesProvider>
  );
};

export default CustomDashboard;
