import { useMemo, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import AddOutlined from '@mui/icons-material/AddOutlined';
import DashboardTimeFilters from '../../../../components/dashboard/DashboardTimeFilters';
import { useFormatter } from '../../../../components/i18n';
import VariableDefinitionDialog from './variables/VariableDefinitionDialog';
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
import DashboardVariablesBar from './variables/DashboardVariablesBar';
import { DashboardVariablesProvider } from './variables/DashboardVariablesContext';
import useDashboardPermissions from '../../../../utils/hooks/useDashboardPermissions';
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
    variables {
      id
      name
      filterKey
      filterKeyType
      defaultValue
      restrictionMode
      restrictionValues
      restrictionFilters
    }
    owner {
      id
      name
      entity_type
    }
    currentUserAccessRight
    ...WorkspaceEditionContainer_workspace
    ...WorkspaceHeaderFragment
    ...DashboardVariablesBar_workspace
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
  userVariableValues?: string | null;
  noToolbar?: boolean;
}

const CustomDashboard = ({ data, userVariableValues, noToolbar = false }: CustomDashboardProps) => {
  const workspace = useFragment(dashboardFragment, data);
  const normalizedUserVariableValues = useMemo(() => {
    const parsedUserVariableValues: Record<string, string> = userVariableValues
      ? (JSON.parse(userVariableValues) as Record<string, string>)
      : {};
    return Object.fromEntries(
      Object.entries(parsedUserVariableValues).filter(([, value]) => typeof value === 'string' && value.length > 0),
    );
  }, [userVariableValues]);
  const [commitWidgetImportMutation] = useApiMutation(dashboardImportWidgetMutation);
  const [addVariableDialogOpen, setAddVariableDialogOpen] = useState(false);
  const { t_i18n } = useFormatter();

  const { canSwitchValues, canEditStructure } = useDashboardPermissions(workspace.currentUserAccessRight);
  const userHasEditAccess = canSwitchValues;
  const userHasUpdateCapa = useGranted([EXPLORE_EXUPDATE]);
  const userCanEdit = canEditStructure;

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

  const usedVariableIds = useMemo(() => {
    const VARIABLE_SENTINEL_PREFIX = '__var__:';
    const ids = new Set<string>();

    const collectVariableIds = (input: unknown) => {
      if (!input) {
        return;
      }
      if (typeof input === 'string') {
        if (input.startsWith(VARIABLE_SENTINEL_PREFIX)) {
          ids.add(input.slice(VARIABLE_SENTINEL_PREFIX.length));
        }
        return;
      }
      if (Array.isArray(input)) {
        input.forEach((value) => collectVariableIds(value));
        return;
      }
      if (typeof input === 'object') {
        const obj = input as Record<string, unknown>;
        Object.values(obj).forEach((value) => collectVariableIds(value));
      }
    };

    helpers.widgetsArray.forEach((widget) => {
      widget.dataSelection.forEach((selection) => {
        collectVariableIds(selection.filters);
        collectVariableIds(selection.dynamicFrom);
        collectVariableIds(selection.dynamicTo);
        (selection.variableBindings ?? []).forEach((binding) => {
          ids.add(binding.variableId);
        });
      });
    });
    return Array.from(ids);
  }, [helpers.widgetsArray]);

  const handleApplyPresetTime = (presetTime: {
    startDate: string | null;
    endDate: string | null;
    relativeDate: string | null;
  }) => {
    if (presetTime.relativeDate) {
      handleDateChange('relativeDate', presetTime.relativeDate);
      return;
    }
    handleDateChange('relativeDate', 'none');
    handleDateChange('startDate', presetTime.startDate);
    handleDateChange('endDate', presetTime.endDate);
  };

  return (
    <DashboardVariablesProvider
      variables={workspace.variables ?? []}
      initialVariableValues={normalizedUserVariableValues}
    >
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
      {!noToolbar && (
        <DashboardVariablesBar
          data={workspace}
          userVariableValues={userVariableValues}
          timeConfig={config}
          onApplyPresetTime={handleApplyPresetTime}
          usedVariableIds={usedVariableIds}
          canEditStructure={canEditStructure}
          canSwitchValues={canSwitchValues}
        />
      )}
      <div id="container">
        <DashboardRefreshProvider refreshToken={refreshToken}>
          {!noToolbar && userHasUpdateCapa && (
            <Box
              sx={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: 1.5,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <DashboardTimeFilters
                  config={config}
                  handleDateChange={handleDateChange}
                />
                {canEditStructure && (
                  <Button
                    startIcon={<AddOutlined />}
                    variant="outlined"
                    size="small"
                    onClick={() => setAddVariableDialogOpen(true)}
                  >
                    {t_i18n('Add variable')}
                  </Button>
                )}
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <DashboardRefreshControl
                  onRefresh={handleManualRefresh}
                  interval={localRefreshRateSeconds}
                  onIntervalChange={handleRefreshRateChange}
                  isRefreshing={isAutoRefreshing}
                />
              </Box>
            </Box>
          )}
          <DashboardContent
            helpers={helpers}
            isEditable={userCanEdit}
            entity={workspace}
            host={WIDGET_WORKSPACE_HOST}
            refreshRate={refreshRate}
          />
        </DashboardRefreshProvider>
      </div>
      <VariableDefinitionDialog
        open={addVariableDialogOpen}
        onClose={() => setAddVariableDialogOpen(false)}
        workspaceId={workspace.id}
      />
    </Stack>
    </DashboardVariablesProvider>
  );
};

export default CustomDashboard;
