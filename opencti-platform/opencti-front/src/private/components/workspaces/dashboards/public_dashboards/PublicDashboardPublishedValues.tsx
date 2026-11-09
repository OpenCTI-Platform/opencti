import React, { useEffect, useMemo } from 'react';
import { useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../../components/i18n';
import useAuth from '../../../../../utils/hooks/useAuth';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardVariableValueInput from '../../../../../components/dashboard/variables/DashboardVariableValueInput';
import { deserializeDashboardManifestForFrontend } from '../../../../../components/dashboard/dashboard-utils';
import {
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
  useEffect(() => {
    const state = buildPublishedValuesState(dashboard, me.id);
    setFieldValue('variable_values', state.variable_values);
    setFieldValue('time_range', state.time_range);
    // Only another dashboard resets the values: a refetch of the same one keeps what the author changed.
  }, [dashboardId]);

  const variables = useMemo(() => {
    const manifest = deserializeDashboardManifestForFrontend(dashboard?.manifest);
    return buildPublishedVariables(manifest.variables ?? [], manifest.widgets);
  }, [dashboard?.manifest]);

  if (!dashboard) return null;

  return (
    <div style={{ marginTop: 20 }} data-testid="public-dashboard-published-values">
      <Typography variant="h4">{t_i18n('Published values')}</Typography>
      <Alert severity="info" variant="outlined" style={{ marginTop: 10 }}>
        {t_i18n('These values are frozen when you publish...')}
      </Alert>
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
