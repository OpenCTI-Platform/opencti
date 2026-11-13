import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import useAuth from '../../../../../utils/hooks/useAuth';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardVariableValueInput from '../../../../../components/dashboard/variables/DashboardVariableValueInput';
import { deserializeDashboardManifestForFrontend } from '../../../../../components/dashboard/dashboard-utils';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { PublicDashboardPublishedValuesQuery } from './__generated__/PublicDashboardPublishedValuesQuery.graphql';
import {
  applyPresetToPublishedValues,
  applyPublishedTimeRangeChange,
  buildPublishedValuesState,
  buildPublishedVariables,
  EMPTY_PUBLISHED_TIME_RANGE,
  type PublicDashboardCreationFormData,
  type PublishableDashboard,
} from './public-dashboard-utils';

interface PublicDashboardPublishedValuesProps {
  dashboard: PublishableDashboard | undefined;
}

/**
 * Values frozen in the public dashboard: its time range and the value of each variable used by a widget.
 * They start from what the author sees on the dashboard, and start again when another dashboard is selected.
 */
const PublicDashboardPublishedValues = ({ dashboard }: PublicDashboardPublishedValuesProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const { values, setFieldValue } = useFormikContext<PublicDashboardCreationFormData>();

  const dashboardId = dashboard?.id;
  // The preset the author started from: a convenience, the fields keep the truth (a snapshot, never a link).
  const [loadedPresetId, setLoadedPresetId] = useState('');
  useEffect(() => {
    const state = buildPublishedValuesState(dashboard, me.id);
    setFieldValue('variable_values', state.variable_values);
    setFieldValue('time_range', state.time_range);
    setLoadedPresetId('');
    // Only another dashboard resets the values: a refetch of the same one keeps what the author changed.
  }, [dashboardId]);

  const variables = useMemo(() => {
    const manifest = deserializeDashboardManifestForFrontend(dashboard?.manifest);
    return buildPublishedVariables(manifest.variables ?? [], manifest.widgets);
  }, [dashboard?.manifest]);

  const presets = dashboard?.presets ?? [];
  const loadPreset = (presetId: string) => {
    setLoadedPresetId(presetId);
    const preset = presets.find((candidate) => candidate.id === presetId);
    if (!preset) return;
    const state = applyPresetToPublishedValues(preset, variables);
    setFieldValue('variable_values', state.variable_values);
    setFieldValue('time_range', state.time_range);
  };

  if (!dashboard) return null;

  return (
    <div style={{ marginTop: 20 }} data-testid="public-dashboard-published-values">
      <Typography variant="h4">{t_i18n('Published values')}</Typography>
      <Alert severity="info" variant="outlined" style={{ marginTop: 10 }}>
        {t_i18n('These values are frozen when you publish...')}
      </Alert>
      {presets.length > 0 && (
        <div style={{ marginTop: 16 }} data-testid="public-dashboard-load-preset">
          <Select value={loadedPresetId} onValueChange={loadPreset} name="load_preset">
            <SelectLabel>{t_i18n('Load a preset')}</SelectLabel>
            <SelectTrigger className="w-full">
              <SelectValue placeholder={t_i18n('Load a preset')} />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Load a preset')}>
              {presets.map((preset) => (
                <SelectItem key={preset.id} value={preset.id}>{preset.name}</SelectItem>
              ))}
            </SelectContent>
            <SelectHelperText>{t_i18n('The variables and time range of the published dashboard start from this preset')}</SelectHelperText>
          </Select>
        </div>
      )}
      <div style={{ marginTop: 16 }}>
        <DashboardTimeFilters
          config={values.time_range}
          handleDateChange={(type, value) => setFieldValue('time_range', applyPublishedTimeRangeChange(values.time_range, type, value))}
        />
      </div>
      {variables.map((variable) => (
        <div key={variable.id} style={{ marginTop: 16 }}>
          <DashboardVariableValueInput
            variable={variable}
            label={variable.name}
            value={values.variable_values[variable.id] ?? ''}
            onChange={(value) => setFieldValue('variable_values', { ...values.variable_values, [variable.id]: value })}
          />
        </div>
      ))}
    </div>
  );
};

export default PublicDashboardPublishedValues;

// Only the selected dashboard is loaded, with its variables, their usage and its presets: the list of the form does not
// carry them for every dashboard.
const publishedValuesQuery = graphql`
  query PublicDashboardPublishedValuesQuery($id: String!) {
    workspace(id: $id) {
      id
      manifest
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
    }
  }
`;

const PublicDashboardPublishedValuesComponent = ({ queryRef }: { queryRef: PreloadedQuery<PublicDashboardPublishedValuesQuery> }) => {
  const { workspace } = usePreloadedQuery<PublicDashboardPublishedValuesQuery>(publishedValuesQuery, queryRef);
  return <PublicDashboardPublishedValues dashboard={workspace ?? undefined} />;
};

const PublicDashboardPublishedValuesFetcher = ({ dashboardId }: { dashboardId: string }) => {
  const { setFieldValue } = useFormikContext<PublicDashboardCreationFormData>();
  const queryRef = useQueryLoading<PublicDashboardPublishedValuesQuery>(publishedValuesQuery, { id: dashboardId });
  // The values of the previous dashboard must not travel with the new id while its data is on its way: the fields
  // are cleared at once, the section fills them again from the dashboard once it arrives.
  useEffect(() => {
    setFieldValue('variable_values', {});
    setFieldValue('time_range', EMPTY_PUBLISHED_TIME_RANGE);
  }, [dashboardId]);
  if (!queryRef) return null;
  return (
    <Suspense fallback={null}>
      <PublicDashboardPublishedValuesComponent queryRef={queryRef} />
    </Suspense>
  );
};

export const PublicDashboardPublishedValuesLoader = ({ dashboardId }: { dashboardId: string | null | undefined }) => {
  // Without a dashboard the section resets its fields through the component itself.
  if (!dashboardId) return <PublicDashboardPublishedValues dashboard={undefined} />;
  return <PublicDashboardPublishedValuesFetcher dashboardId={dashboardId} />;
};
