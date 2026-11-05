import React, { useEffect, useMemo, useState } from 'react';
import { useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import useAuth from '../../../../../utils/hooks/useAuth';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardVariableValueInput from '../../../../../components/dashboard/variables/DashboardVariableValueInput';
import { deserializeDashboardManifestForFrontend } from '../../../../../components/dashboard/dashboard-utils';
import {
  applyPresetToPublishedValues,
  applyPublishedTimeRangeChange,
  buildPublishedValuesState,
  buildPublishedVariables,
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

  const variables = useMemo(
    () => buildPublishedVariables(deserializeDashboardManifestForFrontend(dashboard?.manifest).variables ?? [], dashboard?.variables),
    [dashboard?.manifest, dashboard?.variables],
  );

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
