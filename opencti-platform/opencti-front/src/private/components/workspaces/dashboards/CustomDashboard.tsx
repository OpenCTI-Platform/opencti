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
import { countMissingWidgetVariablesInFile } from '../../../../components/dashboard/import-export/widgetImportVariables';
import DashboardRefreshControl from '../../../../components/dashboard/DashboardRefreshControl';
import { DashboardRefreshProvider } from '../../../../components/dashboard/DashboardRefreshContext';
import { DashboardVariableValuesProvider } from '../../../../components/dashboard/DashboardVariableValuesContext';
import { DashboardVariablesProvider } from '../../../../components/dashboard/DashboardVariablesContext';
import { useDashboardVariables } from '../../../../components/dashboard/useDashboardVariables';
import { useDashboardTimeRange } from '../../../../components/dashboard/useDashboardTimeRange';
import { isSameTimeRange, pickTimeRange } from '../../../../components/dashboard/dashboardTimeRange';
import DashboardValuesActions from '../../../../components/dashboard/DashboardValuesActions';
import DashboardViewerPermissions, { type ViewerPermissions } from '../../../../components/dashboard/DashboardViewerPermissions';
import DashboardVariablesBar from '../../../../components/dashboard/variables/DashboardVariablesBar';
import DashboardVariableDialog from '../../../../components/dashboard/variables/DashboardVariableDialog';
import DashboardVariableDeletion from '../../../../components/dashboard/variables/DashboardVariableDeletion';
import type { DashboardPreset, DashboardVariable } from '../../../../components/dashboard/dashboard-types';
import { useDashboardVariableMutations } from '../../../../components/dashboard/variables/useDashboardVariableMutations';
import DashboardPresetSelector from '../../../../components/dashboard/presets/DashboardPresetSelector';
import DashboardPresetNameDialog from '../../../../components/dashboard/presets/DashboardPresetNameDialog';
import DashboardPresetDeleteDialog from '../../../../components/dashboard/presets/DashboardPresetDeleteDialog';
import { useDashboardPreset } from '../../../../components/dashboard/presets/useDashboardPreset';
import { useDashboardPresetMutations } from '../../../../components/dashboard/presets/useDashboardPresetMutations';
import { isPresetModified, presetFromGraphql, presetInputFromValues } from '../../../../components/dashboard/presets/dashboardPresets';
import { DASHBOARD_VARIABLES_FEATURE_FLAG } from '../../../../components/dashboard/dashboardVariablesFeatureFlag';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from 'src/utils/Security';
import { CustomDashboard_workspace$key } from './__generated__/CustomDashboard_workspace.graphql';
import { CustomDashboardWidgetExportQuery$data } from './__generated__/CustomDashboardWidgetExportQuery.graphql';
import { WIDGET_WORKSPACE_HOST } from './custom-dashboards-utils';
import { CustomDashboardExportQuery } from './__generated__/CustomDashboardExportQuery.graphql';
import { WorkspaceEditionOverviewFieldPatchMutation } from '../__generated__/WorkspaceEditionOverviewFieldPatchMutation.graphql';
import { CustomDashboardLayoutMutation } from './__generated__/CustomDashboardLayoutMutation.graphql';
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
    presets {
      id
      name
      values {
        variableId
        value
      }
      config {
        startDate
        endDate
        relativeDate
      }
    }
    currentUserDefaultPresetId
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
  const [commitManifestPatch] = useApiMutation<WorkspaceEditionOverviewFieldPatchMutation>(workspaceMutationFieldPatch);
  const [commitLayoutPatch] = useApiMutation<CustomDashboardLayoutMutation>(dashboardLayoutMutation);

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
  // undefined: dialog closed, null: saving the current values as a new preset, a preset: renaming it.
  const [presetNameDialog, setPresetNameDialog] = useState<DashboardPreset | null | undefined>(undefined);
  const [presetToDelete, setPresetToDelete] = useState<DashboardPreset | undefined>(undefined);

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

  // Both mutations report every failure, network ones included: the next dashboard write waits for this one to end.
  const onSave = (id: string, newManifestEncoded: string, noRefresh: boolean, onCompleted: () => void, onError: (error: Error) => void) => {
    const commit = noRefresh ? commitLayoutPatch : commitManifestPatch;
    commit({
      variables: { id, input: [{ key: 'manifest', value: [newManifestEncoded] }] },
      onCompleted,
      onError,
    });
  };

  const onImportWidget = async (id: string, widgetConfig: File, manifestEncoded: string) => {
    // An export carries the tokens of the widget, not the variables: the user is told how many are missing here.
    const missingVariables = isVariablesEnabled
      ? await countMissingWidgetVariablesInFile(widgetConfig, new Set(workspace.variables.map((variable) => variable.id)))
      : 0;
    commitWidgetImportMutation({
      variables: {
        id,
        input: {
          importType: 'widget',
          file: widgetConfig,
          dashboardManifest: manifestEncoded,
        },
      },
      onCompleted: () => {
        if (missingVariables > 0) {
          MESSAGING$.notifyWarning(t_i18n('This widget uses variables missing from this dashboard...', { values: { count: missingVariables } }));
        }
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
    && (canManageVariables || config.allowViewersToChangeVariables !== false);
  // The presets of the dashboard, from the server owned key of the manifest.
  const presets = useMemo(() => workspace.presets.map(presetFromGraphql), [workspace.presets]);
  // The selector: editors always (they can at least save one), viewers when they may switch and there is something
  // to switch to.
  const showPresetSelector = isVariablesEnabled && !noToolbar
    && (canManageVariables ? variables.length > 0 || presets.length > 0 : config.allowViewersToSwitchPresets !== false && presets.length > 0);
  const presetControls = useDashboardPreset(workspace.id, presets, {
    ignoreLocalValues: noToolbar || !showPresetSelector,
    enabled: isVariablesEnabled,
    defaultPresetId: workspace.currentUserDefaultPresetId,
  });
  // The active preset (the one of the URL or of this browser, else the one the dashboard opens on for this user:
  // own choice, group or organization) is the base of the values and of the range: its values over the manifest
  // defaults. A shared address holding the preset alone opens its view, and a user who may only switch presets
  // never gets a value from the URL or this browser. The per user changes are kept apart from this base, and
  // Reset goes back to the default preset.
  const { activePreset, defaultPreset } = presetControls;
  const presetBaseValues = useMemo(() => (activePreset ? new Map(Object.entries(activePreset.values)) : undefined), [activePreset]);
  // The home dashboard (noToolbar) and a user without the bar only ever see the base: no per user value is read or written.
  const variableControls = useDashboardVariables(workspace.id, variables, {
    ignoreLocalValues: noToolbar || !showVariablesBar,
    defaultOverrides: presetBaseValues,
  });
  // Flag on, the time range is per user: an editor always gets the time filters, a reader only when viewers may edit
  // them. As for the variables, a user without them only ever sees the base range.
  const showTimeFilters = isVariablesEnabled && !noToolbar
    && (userCanEdit || config.allowViewersToEditTimeFilters !== false);
  const timeRange = useDashboardTimeRange(workspace.id, config, {
    ignoreLocalValues: noToolbar || !showTimeFilters,
    defaultOverride: activePreset?.config ?? null,
  });
  // A preset restores its own values and, for the variables it does not hold, the manifest defaults: not the
  // default preset of the user, so that a preset means the same thing to everyone.
  const isActivePresetModified = activePreset !== null
    && isPresetModified(activePreset, variables, variableControls.manifestDefaults, variableControls.values, timeRange.range);
  // A preset other than the default one is a departure from the defaults in itself: Reset is offered.
  const isPresetSelected = activePreset !== null && activePreset.id !== (defaultPreset?.id ?? null);
  const { upsert: upsertPreset, remove: removePreset, isSubmitting: isPresetSubmitting } = useDashboardPresetMutations(workspace.id);
  // Switching makes the preset the base of the values and of the range at once, and drops the changes made on the
  // previous one; no preset goes back to the default preset, or to the manifest.
  const onSelectPreset = (presetId: string | null) => {
    presetControls.select(presetId);
    variableControls.reset();
    timeRange.reset();
  };
  const onSavePresetAs = async (name: string) => {
    const presetId = await upsertPreset(presetInputFromValues(name, variables, variableControls.values, timeRange.range));
    if (presetId) presetControls.select(presetId);
  };
  const onUpdatePreset = async () => {
    if (!activePreset) return;
    try {
      await upsertPreset(presetInputFromValues(activePreset.name, variables, variableControls.values, timeRange.range, activePreset.id));
    } catch {
      // The mutation already notified the user.
    }
  };
  const onRenamePreset = async (preset: DashboardPreset, name: string) => {
    await upsertPreset({
      id: preset.id,
      name,
      values: Object.entries(preset.values).map(([variableId, value]) => ({ variableId, value })),
      config: preset.config,
    });
  };
  // Deleting the active preset also drops its values and range: the dashboard goes back to the defaults.
  const onDeletePreset = async (preset: DashboardPreset) => {
    await removePreset(preset.id);
    if (activePreset?.id === preset.id) onSelectPreset(null);
  };
  // Mirrors the bar, which renders nothing without variables nor a way to create one.
  const isBarVisible = showVariablesBar && (variables.length > 0 || canManageVariables || showPresetSelector);
  const presetSelector = showPresetSelector ? (
    <DashboardPresetSelector
      presets={presets}
      activePreset={activePreset}
      defaultPreset={defaultPreset}
      isModified={isActivePresetModified}
      canManage={canManageVariables}
      disabled={isPresetSubmitting}
      onSelect={onSelectPreset}
      onSaveAs={canManageVariables ? () => setPresetNameDialog(null) : undefined}
      onUpdate={canManageVariables ? onUpdatePreset : undefined}
      onRename={canManageVariables ? setPresetNameDialog : undefined}
      onDelete={canManageVariables ? setPresetToDelete : undefined}
    />
  ) : null;
  // Summarized by its signature: the widgets re-resolve their filters whenever this set changes.
  const dateVariableIdsSignature = JSON.stringify(variables.filter((variable) => variable.type === 'date').map((variable) => variable.id));
  const dateVariableIds = useMemo(() => new Set<string>(JSON.parse(dateVariableIdsSignature)), [dateVariableIdsSignature]);
  const { setAsDefaults } = useDashboardVariableMutations(workspace.id);
  const usedInWidgetIdsByVariable = useMemo(
    () => new Map(workspace.variables.map((variable) => [variable.id, [...variable.usedInWidgetIds]])),
    [workspace.variables],
  );
  // The same server computation, read the other way round for the widget usage marker.
  const variableNamesByWidget = useMemo(() => {
    const byWidget = new Map<string, string[]>();
    variables.forEach(({ id, name }) => {
      (usedInWidgetIdsByVariable.get(id) ?? []).forEach((widgetId) => {
        byWidget.set(widgetId, [...(byWidget.get(widgetId) ?? []), name]);
      });
    });
    return byWidget;
  }, [variables, usedInWidgetIdsByVariable]);
  // A switch shows its new position at once, disabled until saved; then the saved config takes over, so a failure
  // (already notified by the mutation) puts it back.
  const [pendingPermissions, setPendingPermissions] = useState<ViewerPermissions>({});
  const onPermissionChange = (patch: ViewerPermissions) => {
    setPendingPermissions((current) => ({ ...current, ...patch }));
    handleConfigChange(patch).catch(() => {}).finally(() => {
      setPendingPermissions((current) => {
        const next = { ...current };
        (Object.keys(patch) as (keyof ViewerPermissions)[]).forEach((key) => {
          if (next[key] === patch[key]) delete next[key];
        });
        return next;
      });
    });
  };
  const onReset = () => onSelectPreset(null);
  const onSetAsDefaults = async () => {
    try {
      const submittedValues = variableControls.values;
      const submittedRange = timeRange.range;
      // Compared with the manifest, not with the base of the hook: the range of the active preset, which the
      // manifest does not hold, has to be written too.
      const isRangeModified = !isSameTimeRange(submittedRange, pickTimeRange(config));
      // The variables first: their validation is the step most likely to refuse, and their definitions are then the
      // ones just read. A refused variable stops here, before the range is saved for every viewer.
      await setAsDefaults(variables, submittedValues);
      // The server default now is the submitted value: the local entry is redundant, unless it changed since.
      variableControls.resetValues(submittedValues);
      if (isRangeModified) {
        await handleConfigChange(submittedRange);
        timeRange.resetRange(submittedRange);
      }
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
  // Only the range, memoized on its values: the widgets rebuild their queries when the config identity changes, and
  // saving any other key of the config (a viewer switch) refreshes the manifest.
  const { startDate, endDate, relativeDate } = timeRange.range;
  const contentConfig = useMemo(() => ({ startDate, endDate, relativeDate }), [startDate, endDate, relativeDate]);
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
                  config={{ ...config, ...pendingPermissions }}
                  pending={Object.keys(pendingPermissions) as (keyof ViewerPermissions)[]}
                  onChange={onPermissionChange}
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
                  {!isBarVisible && (timeRange.isModified || isPresetSelected) && (
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
            {/* A viewer who may switch presets but not change the variables gets the selector on its own row. */}
            {!showVariablesBar && presetSelector && (
              <Stack direction="row" sx={{ alignItems: 'center', gap: 1, marginBottom: 1.5 }}>
                {presetSelector}
              </Stack>
            )}
            {showVariablesBar && (
              <DashboardVariablesBar
                leading={presetSelector}
                variables={variables}
                values={variableControls.values}
                defaults={variableControls.defaults}
                usedInWidgetIdsByVariable={usedInWidgetIdsByVariable}
                canManage={canManageVariables}
                isTimeRangeModified={timeRange.isModified}
                isPresetSelected={isPresetSelected}
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
                presets={presets}
                onClose={() => setVariableToDelete(undefined)}
              />
            )}
            {presetNameDialog !== undefined && (
              <DashboardPresetNameDialog
                open
                existingPresets={presets}
                preset={presetNameDialog ?? undefined}
                onConfirm={(name) => (presetNameDialog ? onRenamePreset(presetNameDialog, name) : onSavePresetAs(name))}
                onClose={() => setPresetNameDialog(undefined)}
              />
            )}
            {presetToDelete && (
              <DashboardPresetDeleteDialog
                open
                preset={presetToDelete}
                onConfirm={() => onDeletePreset(presetToDelete)}
                onClose={() => setPresetToDelete(undefined)}
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
                variableNamesByWidget={isVariablesEnabled && !noToolbar ? variableNamesByWidget : undefined}
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
