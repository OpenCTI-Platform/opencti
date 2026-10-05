import React from 'react';
import { graphql, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Grid from '@mui/material/Grid2';
import { Stack, Typography } from '@mui/material';
import { Checkbox } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import EEChip from '@components/common/entreprise_edition/EEChip';
import ObjectLabelField from '@components/common/form/ObjectLabelField';
import type { FieldOption } from '../../../../utils/field';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import notifyMutationOutcome from './notifyMutationOutcome';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { RECOMMENDATION_KIND_LABELS } from './sourceIntelligenceUtils';
import { SourceIntelligenceSettingsQuery } from './__generated__/SourceIntelligenceSettingsQuery.graphql';
import { SourceIntelligenceSettingsEditMutation, SourceRecommendationKind } from './__generated__/SourceIntelligenceSettingsEditMutation.graphql';

export const sourceIntelligenceSettingsFragment = graphql`
  fragment SourceIntelligenceSettings_settings on SourceIntelligenceSettings {
    manager_running
    manager_enabled
    recompute_hour_utc
    backfill_days
    snapshot_retention_days
    corroboration_min_other_sources
    false_positive_labels
    max_scan_objects
    overlap_top
    min_author_volume
    max_author_sources
    min_manual_volume
    max_manual_sources
    value_weights { uniqueness lead_time accuracy relevance impact noise }
    thresholds {
      min_volume low_accuracy quarantine_accuracy high_accuracy raise_confidence_corroboration high_noise
      deny_list_min_false_positives redundant_overlap retire_max_unique_contribution stale_feed_hours gap_coverage
    }
    tuning { confidence_step min_confidence noisy_decay_lifetime_days deny_list_max_values dismiss_cooldown_days min_schedule_minutes }
    autonomy { auto_apply_kinds max_auto_actions_per_run }
    gaps { window_days recent_days target_relationships target_sources max_recommendations }
  }
`;

export const sourceIntelligenceSettingsQuery = graphql`
  query SourceIntelligenceSettingsQuery {
    sourceIntelligenceSettings {
      ...SourceIntelligenceSettings_settings @relay(mask: false)
    }
  }
`;

const sourceIntelligenceSettingsEditMutation = graphql`
  mutation SourceIntelligenceSettingsEditMutation($input: SourceIntelligenceSettingsInput!) {
    sourceIntelligenceSettingsEdit(input: $input) {
      ...SourceIntelligenceSettings_settings @relay(mask: false)
    }
  }
`;

type NumericFieldDefinition = { name: string; label: string; min: number; max: number; step?: number; integer?: boolean };

const GENERAL_FIELDS: NumericFieldDefinition[] = [
  { name: 'recompute_hour_utc', label: 'Nightly computation hour (UTC)', min: 0, max: 23, integer: true },
  { name: 'backfill_days', label: 'History backfill (days)', min: 0, max: 90, integer: true },
  { name: 'snapshot_retention_days', label: 'Snapshot retention (days)', min: 30, max: 1825, integer: true },
  { name: 'corroboration_min_other_sources', label: 'Other sources needed to corroborate', min: 1, max: 10, integer: true },
  { name: 'max_scan_objects', label: 'Maximum scanned objects per computation', min: 1000, max: 50000000, integer: true },
  { name: 'overlap_top', label: 'Overlapping sources kept per scorecard', min: 1, max: 50, integer: true },
  { name: 'min_author_volume', label: 'Minimum volume of an author source', min: 1, max: 100000, integer: true },
  { name: 'max_author_sources', label: 'Maximum author sources', min: 0, max: 5000, integer: true },
  { name: 'min_manual_volume', label: 'Minimum volume of an analyst source', min: 1, max: 100000, integer: true },
  { name: 'max_manual_sources', label: 'Maximum analyst sources', min: 0, max: 2000, integer: true },
];
const WEIGHT_FIELDS: NumericFieldDefinition[] = ['uniqueness', 'lead_time', 'accuracy', 'relevance', 'impact', 'noise']
  .map((key) => ({ name: `value_weights.${key}`, label: `Weight of ${key.replace('_', ' ')}`, min: 0, max: 1, step: 0.05 }));
const THRESHOLD_FIELDS: NumericFieldDefinition[] = [
  { name: 'thresholds.min_volume', label: 'Minimum volume to recommend', min: 0, max: 10000000, integer: true },
  { name: 'thresholds.low_accuracy', label: 'Low accuracy', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.quarantine_accuracy', label: 'Quarantine accuracy', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.high_accuracy', label: 'High accuracy', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.raise_confidence_corroboration', label: 'Corroboration to raise confidence', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.high_noise', label: 'High noise', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.deny_list_min_false_positives', label: 'False positives for a deny list', min: 1, max: 100000, integer: true },
  { name: 'thresholds.redundant_overlap', label: 'Redundant overlap', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.retire_max_unique_contribution', label: 'Unique contribution to retire', min: 0, max: 1, step: 0.01 },
  { name: 'thresholds.stale_feed_hours', label: 'Stale feed (hours)', min: 1, max: 8760, integer: true },
  { name: 'thresholds.gap_coverage', label: 'Coverage below which a criterion is a gap', min: 0, max: 100, integer: true },
];
const TUNING_FIELDS: NumericFieldDefinition[] = [
  { name: 'tuning.confidence_step', label: 'Confidence step', min: 1, max: 50, integer: true },
  { name: 'tuning.min_confidence', label: 'Minimum confidence', min: 0, max: 100, integer: true },
  { name: 'tuning.noisy_decay_lifetime_days', label: 'Decay lifetime for noisy sources (days)', min: 1, max: 3650, integer: true },
  { name: 'tuning.deny_list_max_values', label: 'Maximum values in a deny list', min: 1, max: 100000, integer: true },
  { name: 'tuning.dismiss_cooldown_days', label: 'Cooldown after a rejection (days)', min: 0, max: 365, integer: true },
  { name: 'tuning.min_schedule_minutes', label: 'Minimum schedule (minutes)', min: 5, max: 10080, integer: true },
];
const AUTONOMY_FIELDS: NumericFieldDefinition[] = [
  { name: 'autonomy.max_auto_actions_per_run', label: 'Maximum autonomous actions per computation', min: 0, max: 100, integer: true },
];
const GAP_FIELDS: NumericFieldDefinition[] = [
  { name: 'gaps.window_days', label: 'Coverage window (days)', min: 7, max: 365, integer: true },
  { name: 'gaps.recent_days', label: 'Recent knowledge (days)', min: 1, max: 365, integer: true },
  { name: 'gaps.target_relationships', label: 'Target recent relationships', min: 1, max: 100000, integer: true },
  { name: 'gaps.target_sources', label: 'Target distinct sources', min: 1, max: 50, integer: true },
  { name: 'gaps.max_recommendations', label: 'Recommended integrations per gap', min: 1, max: 20, integer: true },
];
const ALL_NUMERIC_FIELDS = [...GENERAL_FIELDS, ...WEIGHT_FIELDS, ...THRESHOLD_FIELDS, ...TUNING_FIELDS, ...AUTONOMY_FIELDS, ...GAP_FIELDS];

const numberSchema = (field: NumericFieldDefinition, t_i18n: (s: string, options?: { values?: Record<string, unknown> }) => string) => {
  let schema = Yup.number().typeError(t_i18n('This field must be a number')).required(t_i18n('This field is required'))
    .min(field.min, t_i18n('The minimum is {min}', { values: { min: field.min } }))
    .max(field.max, t_i18n('The maximum is {max}', { values: { max: field.max } }));
  if (field.integer) schema = schema.integer(t_i18n('This field must be an integer'));
  return schema;
};

// Nested Yup object from dotted field names (`thresholds.low_accuracy` -> thresholds: { low_accuracy })
const buildValidation = (t_i18n: (s: string, options?: { values?: Record<string, unknown> }) => string) => {
  const root: Record<string, Yup.AnySchema> = {};
  const nested: Record<string, Record<string, Yup.AnySchema>> = {};
  ALL_NUMERIC_FIELDS.forEach((field) => {
    const [head, tail] = field.name.split('.');
    if (tail) {
      nested[head] = { ...(nested[head] ?? {}), [tail]: numberSchema(field, t_i18n) };
    } else {
      root[head] = numberSchema(field, t_i18n);
    }
  });
  Object.entries(nested).forEach(([key, shape]) => {
    root[key] = Yup.object().shape(shape);
  });
  root.false_positive_labels = Yup.array().max(50, t_i18n('At most {max} labels', { values: { max: 50 } }));
  return Yup.object().shape(root);
};

// The setting stores label values, matched case-insensitively: a label picked in the list is the one already listed
const labelValue = (option: FieldOption) => option.label.trim().toLowerCase();
const isSameLabel = (a: FieldOption, b: FieldOption) => labelValue(a) === labelValue(b);

type SettingsData = NonNullable<SourceIntelligenceSettingsQuery['response']['sourceIntelligenceSettings']>;

const toNumbers = <T extends Record<string, unknown>>(value: T): T => Object.fromEntries(
  Object.entries(value).map(([key, v]) => [key, typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v)) ? Number(v) : v]),
) as T;

interface SettingsFormProps {
  queryRef: PreloadedQuery<SourceIntelligenceSettingsQuery>;
}

const SourceIntelligenceSettingsForm = ({ queryRef }: SettingsFormProps) => {
  const { t_i18n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { sourceIntelligenceSettings } = usePreloadedQuery(sourceIntelligenceSettingsQuery, queryRef);
  const [commit] = useApiMutation<SourceIntelligenceSettingsEditMutation>(sourceIntelligenceSettingsEditMutation);
  if (!sourceIntelligenceSettings) {
    return null;
  }
  const settings: SettingsData = sourceIntelligenceSettings;
  const initialValues = {
    ...settings,
    false_positive_labels: settings.false_positive_labels.map((value): FieldOption => ({ label: value, value })),
    autonomy: { ...settings.autonomy, auto_apply_kinds: [...settings.autonomy.auto_apply_kinds] as string[] },
  };

  const renderFields = (fields: NumericFieldDefinition[]) => (
    <Grid container spacing={2}>
      {fields.map((field) => (
        <Grid key={field.name} size={{ xs: 12, sm: 6, md: 4 }}>
          <Field
            component={TextField}
            variant="standard"
            type="number"
            name={field.name}
            label={t_i18n(field.label)}
            fullWidth
            inputProps={{ min: field.min, max: field.max, step: field.step ?? 1 }}
          />
        </Grid>
      ))}
    </Grid>
  );

  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={buildValidation(t_i18n)}
      onSubmit={(values, { setSubmitting }) => {
        const input = {
          ...toNumbers({
            recompute_hour_utc: values.recompute_hour_utc,
            backfill_days: values.backfill_days,
            snapshot_retention_days: values.snapshot_retention_days,
            corroboration_min_other_sources: values.corroboration_min_other_sources,
            max_scan_objects: values.max_scan_objects,
            overlap_top: values.overlap_top,
            min_author_volume: values.min_author_volume,
            max_author_sources: values.max_author_sources,
            min_manual_volume: values.min_manual_volume,
            max_manual_sources: values.max_manual_sources,
          }),
          manager_running: values.manager_running,
          false_positive_labels: Array.from(new Set(values.false_positive_labels.map(labelValue).filter((label) => label.length > 0))),
          value_weights: toNumbers({ ...values.value_weights }),
          thresholds: toNumbers({ ...values.thresholds }),
          tuning: toNumbers({ ...values.tuning }),
          ...(isEnterpriseEdition ? {
            autonomy: {
              auto_apply_kinds: values.autonomy.auto_apply_kinds as SourceRecommendationKind[],
              max_auto_actions_per_run: Number(values.autonomy.max_auto_actions_per_run),
            },
            gaps: toNumbers({ ...values.gaps }),
          } : {}),
        };
        commit({
          variables: { input },
          // The settings have no Relay identity: the saved ones replace those the page reads, and the form reinitializes
          updater: (store) => {
            const saved = store.getRootField('sourceIntelligenceSettingsEdit');
            if (saved) {
              store.getRoot().setLinkedRecord(saved, 'sourceIntelligenceSettings');
            }
          },
          onCompleted: (_, errors) => {
            setSubmitting(false);
            notifyMutationOutcome(errors, { success: t_i18n('Source intelligence settings saved') });
          },
          onError: () => setSubmitting(false),
        });
      }}
    >
      {({ isSubmitting, values, setFieldValue, dirty }) => (
        <Form data-testid="source-intelligence-settings-form">
          <Stack gap={2}>
            <Card title={t_i18n('Computation')}>
              <Field
                component={SwitchField}
                type="checkbox"
                name="manager_running"
                label={t_i18n('Compute the source scorecards')}
                disabled={!settings.manager_enabled}
                helpertext={settings.manager_enabled
                  ? undefined
                  : t_i18n('The source intelligence manager is disabled in the platform configuration: the scorecards are not computed whatever this setting.')}
              />
              {renderFields(GENERAL_FIELDS)}
              <ObjectLabelField
                name="false_positive_labels"
                label={t_i18n('False positive labels')}
                helpertext={t_i18n('Objects carrying one of these labels count as false positives of their sources, for example false-positive. Left empty, no label marks an object as a false positive.')}
                style={{ marginTop: 16 }}
                setFieldValue={setFieldValue}
                values={values.false_positive_labels}
                isOptionEqualToValue={isSameLabel}
              />
            </Card>
            <Card title={t_i18n('Operational value score weights')}>
              <Typography variant="body2" sx={{ marginBottom: 2 }}>
                {t_i18n('Components that cannot be measured for a source are excluded from its score instead of counting as zero.')}
              </Typography>
              {renderFields(WEIGHT_FIELDS)}
            </Card>
            <Card title={<Stack direction="row" gap={1} alignItems="center">{t_i18n('Recommendation thresholds')}{!isEnterpriseEdition && <EEChip />}</Stack>}>
              {renderFields(THRESHOLD_FIELDS)}
            </Card>
            <Card title={<Stack direction="row" gap={1} alignItems="center">{t_i18n('Tuning')}{!isEnterpriseEdition && <EEChip />}</Stack>}>
              {renderFields(TUNING_FIELDS)}
            </Card>
            {isEnterpriseEdition && (
              <>
                <Card title={t_i18n('Autonomy policy')}>
                  <Typography variant="body2" sx={{ marginBottom: 2 }}>
                    {t_i18n('Recommendations of the selected kinds are applied automatically after each computation, within the limit below. Every autonomous action is audited and can be reverted.')}
                  </Typography>
                  <Grid container spacing={1} sx={{ marginBottom: 2 }}>
                    {Object.entries(RECOMMENDATION_KIND_LABELS)
                      .filter(([kind]) => kind !== 'add_connector')
                      .map(([kind, label]) => (
                        <Grid key={kind} size={{ xs: 12, sm: 6, md: 3 }}>
                          <Checkbox
                            label={t_i18n(label)}
                            checked={values.autonomy.auto_apply_kinds.includes(kind)}
                            onCheckedChange={(checked) => {
                              const current = values.autonomy.auto_apply_kinds;
                              setFieldValue('autonomy.auto_apply_kinds', checked === true
                                ? [...current, kind]
                                : current.filter((k) => k !== kind));
                            }}
                            data-testid={`source-intelligence-autonomy-${kind}`}
                          />
                        </Grid>
                      ))}
                  </Grid>
                  {renderFields(AUTONOMY_FIELDS)}
                </Card>
                <Card title={t_i18n('Collection gaps')}>
                  {renderFields(GAP_FIELDS)}
                </Card>
              </>
            )}
            <Stack direction="row" justifyContent="flex-end">
              <Button type="submit" disabled={isSubmitting || !dirty} data-testid="source-intelligence-settings-submit">
                {t_i18n('Save')}
              </Button>
            </Stack>
          </Stack>
        </Form>
      )}
    </Formik>
  );
};

const SourceIntelligenceSettings = () => {
  const queryRef = useQueryLoading<SourceIntelligenceSettingsQuery>(sourceIntelligenceSettingsQuery, {});
  if (!queryRef) {
    return <Loader variant={LoaderVariant.inElement} />;
  }
  return (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <SourceIntelligenceSettingsForm queryRef={queryRef} />
    </React.Suspense>
  );
};

export default SourceIntelligenceSettings;
