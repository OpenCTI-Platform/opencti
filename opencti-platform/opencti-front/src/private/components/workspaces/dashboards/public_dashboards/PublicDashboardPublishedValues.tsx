import React, { useEffect, useMemo, useState } from 'react';
import { useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useAuth from '../../../../../utils/hooks/useAuth';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardVariableValueInput from '../../../../../components/dashboard/variables/DashboardVariableValueInput';
import { deserializeDashboardManifestForFrontend } from '../../../../../components/dashboard/dashboard-utils';
import {
  applyPublishedTimeRangeChange,
  applyPublishedVariableChange,
  buildPublishedValuesState,
  buildPublishedVariables,
  type PublicDashboardCreationFormData,
  isTypedPublishedVariable,
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
  const theme = useTheme<Theme>();
  const { me } = useAuth();
  const { values, errors, setFieldValue, setValues } = useFormikContext<PublicDashboardCreationFormData>();

  // A cleared picker is given its default back: when that default is the value it held, the form value does not change
  // and the picker would keep its emptied text. Remounting it shows the value again.
  const [revisions, setRevisions] = useState<Record<string, number>>({});

  // The pickers that show a date they refuse: the form cannot be published while one of them is in use.
  const [invalidDates, setInvalidDates] = useState<Record<string, boolean>>({});
  const hasInvalidDate = values.time_range.relativeDate === null && Object.values(invalidDates).some(Boolean);
  useEffect(() => {
    if (hasInvalidDate !== !!values.time_range_invalid) setFieldValue('time_range_invalid', hasInvalidDate);
  }, [hasInvalidDate, values.time_range_invalid]);

  const dashboardId = dashboard?.id;
  useEffect(() => {
    const state = buildPublishedValuesState(dashboard, me.id);
    // One update: each setFieldValue validates the values of the last render, so a second one would validate them
    // without the first. A refused date of the previous dashboard no longer counts (the pickers start again).
    setValues((current) => ({ ...current, ...state, time_range_invalid: false }));
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
          onInvalidDateChange={(type, invalid) => setInvalidDates((current) => (current[type] === invalid ? current : { ...current, [type]: invalid }))}
        />
        {typeof errors.time_range_invalid === 'string' && (
          <Text
            variant="content-caption"
            as="p"
            role="alert"
            style={{ color: theme.palette.error.main, marginTop: 4 }}
            data-testid="public-dashboard-published-date-error"
          >
            {errors.time_range_invalid}
          </Text>
        )}
        {typeof errors.time_range === 'string' && (
          <Text
            variant="content-caption"
            as="p"
            role="alert"
            style={{ color: theme.palette.error.main, marginTop: 4 }}
            data-testid="public-dashboard-published-range-error"
          >
            {errors.time_range}
          </Text>
        )}
      </div>
      {variables.map((variable) => {
        const value = values.variable_values[variable.id] ?? '';
        // An empty typed field publishes the default of the variable: said under the field, as the author types.
        const showsDefault = value === '' && isTypedPublishedVariable(variable) && !!variable.defaultValue;
        // Without a default there is nothing to publish for an empty field, and a widget uses the variable.
        const isMissing = value === '' && !variable.defaultValue;
        return (
          <div key={variable.id} style={{ marginTop: 16 }}>
            <DashboardVariableValueInput
              key={revisions[variable.id] ?? 0}
              variable={variable}
              label={variable.name}
              value={value}
              onChange={(next) => {
                const applied = applyPublishedVariableChange(variable, next);
                setFieldValue('variable_values', { ...values.variable_values, [variable.id]: applied });
                if (applied !== next) setRevisions((current) => ({ ...current, [variable.id]: (current[variable.id] ?? 0) + 1 }));
              }}
            />
            {showsDefault && (
              <Text
                variant="content-caption"
                as="p"
                style={{ color: theme.palette.text.secondary, marginTop: 4 }}
                data-testid={`public-dashboard-published-default-${variable.id}`}
              >
                {t_i18n('Empty: the default value {value} is published', { values: { value: variable.defaultValue } })}
              </Text>
            )}
            {isMissing && (
              <Text
                variant="content-caption"
                as="p"
                role="alert"
                style={{ color: theme.palette.error.main, marginTop: 4 }}
                data-testid={`public-dashboard-published-missing-${variable.id}`}
              >
                {t_i18n('This field is required')}
              </Text>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default PublicDashboardPublishedValues;
