import React, { Suspense, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/material/styles';
import { Select, SelectContent, SelectHelperText, SelectItem, SelectLabel, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import useAuth from '../../../../../utils/hooks/useAuth';
import DashboardTimeFilters from '../../../../../components/dashboard/DashboardTimeFilters';
import DashboardVariableValueInput from '../../../../../components/dashboard/variables/DashboardVariableValueInput';
import { deserializeDashboardManifestForFrontend } from '../../../../../components/dashboard/dashboard-utils';
import useQueryLoading from '../../../../../utils/hooks/useQueryLoading';
import { PublicDashboardPublishedValuesQuery } from './__generated__/PublicDashboardPublishedValuesQuery.graphql';
import {
  applyPresetToPublishedValues,
  applyPublishedTimeRangeChange,
  applyPublishedVariableChange,
  buildPublishedValuesState,
  buildPublishedVariables,
  EMPTY_PUBLISHED_TIME_RANGE,
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
  // The preset the author started from: a convenience, the fields keep the truth (a snapshot, never a link).
  const [loadedPresetId, setLoadedPresetId] = useState('');
  useEffect(() => {
    const state = buildPublishedValuesState(dashboard, me.id);
    // One update: each setFieldValue validates the values of the last render, so a second one would validate them
    // without the first. A refused date of the previous dashboard no longer counts (the pickers start again).
    setValues((current) => ({ ...current, ...state, published_for: dashboardId ?? null, time_range_invalid: false }));
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
    setValues((current) => ({ ...current, ...state }));
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

// Only the selected dashboard is loaded, with its variables, their usage and its presets: the list of the form does not
// carry them for every dashboard.
const publishedValuesQuery = graphql`
  query PublicDashboardPublishedValuesQuery($id: String!) {
    workspace(id: $id) {
      id
      manifest
      currentUserDefaultPresetId
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
  const { setValues } = useFormikContext<PublicDashboardCreationFormData>();
  const queryRef = useQueryLoading<PublicDashboardPublishedValuesQuery>(publishedValuesQuery, { id: dashboardId });
  // The values of the previous dashboard must not travel with the new id while its data is on its way: the fields
  // are cleared at once, the section fills them again from the dashboard once it arrives.
  useEffect(() => {
    setValues((current) => ({ ...current, variable_values: {}, time_range: EMPTY_PUBLISHED_TIME_RANGE, published_for: null, time_range_invalid: false }));
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
