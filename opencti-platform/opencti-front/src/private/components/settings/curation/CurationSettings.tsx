import { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Field, FieldArray, Form, Formik } from 'formik';
import * as Yup from 'yup';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { DeleteOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Card from '@common/card/Card';
import Tag from '@common/tag/Tag';
import EEChip from '@components/common/entreprise_edition/EEChip';
import ObjectMembersField from '@components/common/form/ObjectMembersField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import ComboboxField from '../../../../components/ComboboxField';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import type { Theme } from '../../../../components/Theme';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import useAuth from '../../../../utils/hooks/useAuth';
import { MESSAGING$ } from '../../../../relay/environment';
import CurationAuthoritySourcesField, { AuthoritySourceOption, toAuthoritySourceOption } from './CurationAuthoritySourcesField';
import useCurationLabels, { CURATION_RELATIONSHIP_CONFLICT_MODES, CURATION_WEEK_DAYS, notifyPayloadErrors } from '../../data/curation/curationUtils';
import { CurationSettingsQuery, CurationSettingsQuery$data } from './__generated__/CurationSettingsQuery.graphql';
import { CurationSettingsEditMutation } from './__generated__/CurationSettingsEditMutation.graphql';
import { CurationSettingsScanMutation } from './__generated__/CurationSettingsScanMutation.graphql';

export const curationSettingsFragment = graphql`
  fragment CurationSettings_settings on CurationSettings {
    id
    curation_enabled
    enabled_detectors
    available_detectors
    curated_entity_types
    similarity_threshold
    description_similarity_enabled
    description_similarity_threshold
    graph_similarity_available
    provenance_available
    behavior_threshold
    proposal_min_confidence
    ambiguous_band_min
    ambiguous_band_max
    adjudication_enabled
    adjudication_available
    adjudication_agent_slug
    adjudication_run_as_id
    adjudication_run_as {
      id
      name
      entity_type
    }
    adjudication_daily_limit
    stale_default_months
    stale_overrides {
      entity_type
      months
    }
    relationship_conflict_mode
    procedures_attribute_available
    merge_record_retention_days
    digest_enabled
    digest_day
    digest_recipients {
      id
      name
      entity_type
    }
    field_authority_enabled
    field_authority_rules {
      entity_type
      attribute
      sources {
        source_type
        source_id
        source_name
      }
    }
    authority_connector_sources {
      source_type
      source_id
      source_name
    }
    scan_max_entities_per_type
    force_scan
    last_scan_date
    last_snapshot_date
    last_digest_date
    taxonomy_version
    taxonomy_clusters_count
  }
`;

const curationSettingsQuery = graphql`
  query CurationSettingsQuery {
    curationSettings {
      ...CurationSettings_settings @relay(mask: false)
    }
  }
`;

const curationSettingsEditMutation = graphql`
  mutation CurationSettingsEditMutation($input: CurationSettingsInput!) {
    curationSettingsEdit(input: $input) {
      ...CurationSettings_settings @relay(mask: false)
    }
  }
`;

const curationScanMutation = graphql`
  mutation CurationSettingsScanMutation {
    curationScanRequest {
      id
      force_scan
    }
  }
`;

type Settings = CurationSettingsQuery$data['curationSettings'];

interface RuleValues {
  entity_type: string;
  attribute: string;
  sources: AuthoritySourceOption[];
}

interface SettingsValues {
  curation_enabled: boolean;
  enabled_detectors: FieldOption[];
  curated_entity_types: FieldOption[];
  scan_max_entities_per_type: number | string;
  similarity_threshold: number | string;
  description_similarity_enabled: boolean;
  description_similarity_threshold: number | string;
  behavior_threshold: number | string;
  proposal_min_confidence: number | string;
  ambiguous_band_min: number | string;
  ambiguous_band_max: number | string;
  adjudication_enabled: boolean;
  adjudication_agent_slug: string;
  adjudication_run_as: FieldOption | null;
  adjudication_daily_limit: number | string;
  stale_default_months: number | string;
  stale_overrides: Array<{ entity_type: string; months: number | string }>;
  relationship_conflict_mode: string;
  merge_record_retention_days: number | string;
  digest_enabled: boolean;
  digest_day: string;
  digest_recipients: FieldOption[];
  field_authority_enabled: boolean;
  field_authority_rules: RuleValues[];
}

const numberField = (min: number, max: number, message: string, integer = false) => {
  const base = Yup.number().typeError(message).min(min, message).max(max, message).required(message);
  return integer ? base.integer(message) : base;
};

const CurationSettingsForm = ({ settings }: { settings: Settings }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const labels = useCurationLabels();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { schema } = useAuth();
  const [commitEdit] = useApiMutation<CurationSettingsEditMutation>(curationSettingsEditMutation);
  const [commitScan, scanning] = useApiMutation<CurationSettingsScanMutation>(curationScanMutation);
  const [scanRequested, setScanRequested] = useState(settings.force_scan);
  const typeOption = (type: string): FieldOption => ({ value: type, label: t_i18n(`entity_${type}`) });
  const detectorOption = (detector: string): FieldOption => ({ value: detector, label: labels.detector(detector) });
  const knowledgeTypes = [...(schema?.sdos ?? []).map((sdo) => sdo.id), 'Indicator']
    .filter((type, index, all) => all.indexOf(type) === index)
    .sort((left, right) => t_i18n(`entity_${left}`).localeCompare(t_i18n(`entity_${right}`)));
  const connectorOptions = settings.authority_connector_sources.map((source) => toAuthoritySourceOption('connector', source.source_id, source.source_name, t_i18n('Connector')));
  const memberOption = (member: { id: string; name: string; entity_type: string }): FieldOption => ({ value: member.id, label: member.name, type: member.entity_type });

  const initialValues: SettingsValues = {
    curation_enabled: settings.curation_enabled,
    enabled_detectors: settings.enabled_detectors.map(detectorOption),
    curated_entity_types: settings.curated_entity_types.map(typeOption),
    scan_max_entities_per_type: settings.scan_max_entities_per_type,
    similarity_threshold: settings.similarity_threshold,
    description_similarity_enabled: settings.description_similarity_enabled,
    description_similarity_threshold: settings.description_similarity_threshold,
    behavior_threshold: settings.behavior_threshold,
    proposal_min_confidence: settings.proposal_min_confidence,
    ambiguous_band_min: settings.ambiguous_band_min,
    ambiguous_band_max: settings.ambiguous_band_max,
    adjudication_enabled: settings.adjudication_enabled,
    adjudication_agent_slug: settings.adjudication_agent_slug ?? '',
    adjudication_run_as: settings.adjudication_run_as ? memberOption(settings.adjudication_run_as) : null,
    adjudication_daily_limit: settings.adjudication_daily_limit,
    stale_default_months: settings.stale_default_months,
    stale_overrides: settings.stale_overrides.map((override) => ({ entity_type: override.entity_type, months: override.months })),
    relationship_conflict_mode: settings.relationship_conflict_mode,
    merge_record_retention_days: settings.merge_record_retention_days,
    digest_enabled: settings.digest_enabled,
    digest_day: String(settings.digest_day),
    digest_recipients: settings.digest_recipients.map(memberOption),
    field_authority_enabled: settings.field_authority_enabled,
    field_authority_rules: settings.field_authority_rules.map((rule) => ({
      entity_type: rule.entity_type,
      attribute: rule.attribute,
      sources: rule.sources.map((source) => {
        const sourceType = source.source_type === 'connector' ? 'connector' : 'author';
        return toAuthoritySourceOption(sourceType, source.source_id, source.source_name, sourceType === 'connector' ? t_i18n('Connector') : t_i18n('Author'));
      }),
    })),
  };

  const rate = t_i18n('The value must be between 0 and 1');
  const validation = Yup.object().shape({
    scan_max_entities_per_type: numberField(100, 100000, t_i18n('The value must be between 100 and 100000'), true),
    similarity_threshold: numberField(0.5, 1, t_i18n('The value must be between 0.5 and 1')),
    description_similarity_threshold: numberField(0.5, 1, t_i18n('The value must be between 0.5 and 1')),
    behavior_threshold: numberField(0.1, 1, t_i18n('The value must be between 0.1 and 1')),
    proposal_min_confidence: numberField(0, 1, rate),
    ambiguous_band_min: numberField(0, 1, rate),
    ambiguous_band_max: numberField(0, 1, rate)
      .moreThan(Yup.ref('ambiguous_band_min'), t_i18n('The ambiguous band maximum must be greater than its minimum')),
    adjudication_daily_limit: numberField(0, 10000, t_i18n('The value must be between 0 and 10000'), true),
    stale_default_months: numberField(1, 240, t_i18n('The value must be between 1 and 240'), true),
    stale_overrides: Yup.array().of(Yup.object().shape({
      entity_type: Yup.string().required(t_i18n('This field is required')),
      months: numberField(1, 240, t_i18n('The value must be between 1 and 240'), true),
    })),
    merge_record_retention_days: numberField(1, 3650, t_i18n('The value must be between 1 and 3650'), true),
    field_authority_rules: Yup.array().of(Yup.object().shape({
      entity_type: Yup.string().required(t_i18n('This field is required')),
      attribute: Yup.string().trim().required(t_i18n('This field is required')),
      sources: Yup.array().min(1, t_i18n('Select at least one source')).max(20, t_i18n('Select at most 20 sources')),
    })).max(200),
  });

  const onSubmit = (values: SettingsValues, { setSubmitting }: { setSubmitting: (flag: boolean) => void }) => {
    const input = {
      curation_enabled: values.curation_enabled,
      enabled_detectors: values.enabled_detectors.map((option) => option.value),
      curated_entity_types: values.curated_entity_types.map((option) => option.value),
      scan_max_entities_per_type: Number(values.scan_max_entities_per_type),
      similarity_threshold: Number(values.similarity_threshold),
      description_similarity_enabled: values.description_similarity_enabled,
      description_similarity_threshold: Number(values.description_similarity_threshold),
      behavior_threshold: Number(values.behavior_threshold),
      proposal_min_confidence: Number(values.proposal_min_confidence),
      ambiguous_band_min: Number(values.ambiguous_band_min),
      ambiguous_band_max: Number(values.ambiguous_band_max),
      adjudication_enabled: isEnterpriseEdition ? values.adjudication_enabled : false,
      adjudication_agent_slug: values.adjudication_agent_slug.trim() || null,
      adjudication_run_as_id: values.adjudication_run_as?.value ?? null,
      adjudication_daily_limit: Number(values.adjudication_daily_limit),
      stale_default_months: Number(values.stale_default_months),
      stale_overrides: values.stale_overrides.map((override) => ({ entity_type: override.entity_type, months: Number(override.months) })),
      relationship_conflict_mode: values.relationship_conflict_mode,
      merge_record_retention_days: Number(values.merge_record_retention_days),
      digest_enabled: values.digest_enabled,
      digest_day: Number(values.digest_day),
      digest_recipient_ids: values.digest_recipients.map((option) => option.value),
      field_authority_enabled: values.field_authority_enabled,
      field_authority_rules: values.field_authority_rules.map((rule) => ({
        entity_type: rule.entity_type,
        attribute: rule.attribute.trim(),
        sources: rule.sources.map((source) => ({ source_type: source.source_type, source_id: source.source_id })),
      })),
    };
    commitEdit({
      variables: { input: input as never },
      onCompleted: (_, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The curation settings have been saved'));
      },
      onError: () => setSubmitting(false),
    });
  };

  const requestScan = () => {
    commitScan({
      variables: {},
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        setScanRequested(true);
        MESSAGING$.notifySuccess(t_i18n('A full curation scan will start at the next manager cycle'));
      },
    });
  };

  const dateOrNever = (date: string | null | undefined) => (date ? fldt(date) : t_i18n('Never'));

  return (
    <Formik<SettingsValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit} enableReinitialize>
      {({ submitForm, isSubmitting, values, dirty }) => (
        <Form data-testid="curation-settings-form">
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, marginBottom: 2 }}>
            <Typography variant="body2" sx={{ flex: 1 }} color={theme.palette.text.light}>
              {t_i18n('Last scan')}: {dateOrNever(settings.last_scan_date)} - {t_i18n('Last Knowledge Health snapshot')}: {dateOrNever(settings.last_snapshot_date)} - {t_i18n('Last weekly digest')}: {dateOrNever(settings.last_digest_date)}
            </Typography>
            <Button variant="secondary" onClick={requestScan} disabled={scanning || scanRequested} data-testid="curation-scan-request">
              {scanRequested ? t_i18n('Scan scheduled') : t_i18n('Run a scan now')}
            </Button>
            <Button onClick={submitForm} disabled={isSubmitting || !dirty} data-testid="curation-settings-save">
              {t_i18n('Save')}
            </Button>
          </Box>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <Card title={t_i18n('Detection')}>
              <Field component={SwitchField} type="checkbox" name="curation_enabled" label={t_i18n('Enable knowledge curation')} />
              <Field
                component={ComboboxField}
                name="enabled_detectors"
                multiple={true}
                label={t_i18n('Enabled detectors')}
                options={settings.available_detectors.map(detectorOption)}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={ComboboxField}
                name="curated_entity_types"
                multiple={true}
                label={t_i18n('Curated entity types')}
                options={knowledgeTypes.map(typeOption)}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="scan_max_entities_per_type"
                label={t_i18n('Maximum entities scanned per type')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', marginTop: 2 }}>
                <Tag label={`${t_i18n('Vendor taxonomy')} ${settings.taxonomy_version} - ${settings.taxonomy_clusters_count} ${t_i18n('clusters')}`} />
                <Tag label={settings.graph_similarity_available ? t_i18n('Graph similarity available') : t_i18n('Graph similarity not available')} />
                <Tag label={settings.provenance_available ? t_i18n('Source provenance available') : t_i18n('Source provenance not available')} />
              </Box>
            </Card>
            <Card title={t_i18n('Thresholds')}>
              <Field component={TextField} variant="standard" type="number" name="similarity_threshold" label={t_i18n('Name similarity threshold (0.5 to 1)')} fullWidth={true} />
              <Field component={SwitchField} type="checkbox" name="description_similarity_enabled" label={t_i18n('Compare descriptions')} containerstyle={fieldSpacingContainerStyle} />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="description_similarity_threshold"
                label={t_i18n('Description similarity threshold (0.5 to 1)')}
                disabled={!values.description_similarity_enabled}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field component={TextField} variant="standard" type="number" name="behavior_threshold" label={t_i18n('Behavior overlap threshold (0.1 to 1)')} fullWidth={true} style={fieldSpacingContainerStyle} />
              <Field component={TextField} variant="standard" type="number" name="proposal_min_confidence" label={t_i18n('Minimum proposal confidence (0 to 1)')} fullWidth={true} style={fieldSpacingContainerStyle} />
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                <Field component={TextField} variant="standard" type="number" name="ambiguous_band_min" label={t_i18n('Ambiguous band minimum')} fullWidth={true} style={fieldSpacingContainerStyle} />
                <Field component={TextField} variant="standard" type="number" name="ambiguous_band_max" label={t_i18n('Ambiguous band maximum')} fullWidth={true} style={fieldSpacingContainerStyle} />
              </Box>
            </Card>
            <Card title={<Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{t_i18n('Adjudication by XTM One')}<EEChip /></Box>}>
              <Typography variant="body2" color={theme.palette.text.light} sx={{ marginBottom: 1 }}>
                {settings.adjudication_available
                  ? t_i18n('Proposals in the ambiguous band are sent to the agent bound to the cti.curation_adjudicate intent.')
                  : t_i18n('Adjudication needs the Enterprise Edition and a configured XTM One.')}
              </Typography>
              <Field
                component={SwitchField}
                type="checkbox"
                name="adjudication_enabled"
                label={t_i18n('Enable adjudication')}
                disabled={!isEnterpriseEdition || !settings.adjudication_available}
              />
              <Field
                component={TextField}
                variant="standard"
                name="adjudication_agent_slug"
                label={t_i18n('Agent (slug, optional: the highest priority bound agent otherwise)')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <ObjectMembersField
                name="adjudication_run_as"
                label={t_i18n('Run as (optional)')}
                multiple={false}
                entityTypes={['User']}
                style={fieldSpacingContainerStyle}
              />
              <Field component={TextField} variant="standard" type="number" name="adjudication_daily_limit" label={t_i18n('Daily adjudication limit')} fullWidth={true} style={fieldSpacingContainerStyle} />
            </Card>
            <Card title={t_i18n('Staleness, conflicts and merges')}>
              <Field component={TextField} variant="standard" type="number" name="stale_default_months" label={t_i18n('Stale after (months, default)')} fullWidth={true} />
              <FieldArray name="stale_overrides">
                {({ push, remove }) => (
                  <Box sx={{ marginTop: 2 }}>
                    {values.stale_overrides.map((_, index) => (
                      <Box key={index} sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr auto', gap: 1, alignItems: 'end' }}>
                        <Field component={SelectFieldFds} name={`stale_overrides.${index}.entity_type`} label={t_i18n('Entity type')} fullWidth={true}>
                          {knowledgeTypes.map((type) => <SelectItem key={type} value={type}>{t_i18n(`entity_${type}`)}</SelectItem>)}
                        </Field>
                        <Field component={TextField} variant="standard" type="number" name={`stale_overrides.${index}.months`} label={t_i18n('Months')} fullWidth={true} />
                        <IconButton size="small" aria-label={t_i18n('Delete')} title={t_i18n('Delete')} onClick={() => remove(index)}>
                          <DeleteOutlined fontSize="small" />
                        </IconButton>
                      </Box>
                    ))}
                    <Button size="small" variant="tertiary" onClick={() => push({ entity_type: '', months: 12 })}>
                      {t_i18n('Add a staleness override')}
                    </Button>
                  </Box>
                )}
              </FieldArray>
              <Field
                component={SelectFieldFds}
                name="relationship_conflict_mode"
                label={t_i18n('Procedures of uses relationships')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                {CURATION_RELATIONSHIP_CONFLICT_MODES.map((mode) => <SelectItem key={mode} value={mode}>{labels.conflictMode(mode)}</SelectItem>)}
              </Field>
              {values.relationship_conflict_mode === 'procedures_array' && !settings.procedures_attribute_available && (
                <Typography variant="caption" color="warning.main">
                  {t_i18n('This platform has no procedures attribute on uses relationships: the procedure is kept in a note instead.')}
                </Typography>
              )}
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="merge_record_retention_days"
                label={t_i18n('Merges stay reversible for (days)')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
            </Card>
            <Card title={t_i18n('Knowledge Health weekly digest')}>
              <Field component={SwitchField} type="checkbox" name="digest_enabled" label={t_i18n('Send the weekly digest')} />
              <Field component={SelectFieldFds} name="digest_day" label={t_i18n('Day of the week (UTC)')} fullWidth={true} containerstyle={fieldSpacingContainerStyle}>
                {CURATION_WEEK_DAYS.map((day) => <SelectItem key={day} value={String(day)}>{labels.weekDay(day)}</SelectItem>)}
              </Field>
              <ObjectMembersField name="digest_recipients" label={t_i18n('Recipients (users, groups or organizations)')} multiple={true} style={fieldSpacingContainerStyle} />
            </Card>
            <Card title={t_i18n('Field authority')}>
              <Typography variant="body2" color={theme.palette.text.light} sx={{ marginBottom: 1 }}>
                {t_i18n('A merge policy for upserts: on a ruled attribute, a more authoritative source wins and a less authoritative one loses, before the confidence comparison.')}
              </Typography>
              <Field component={SwitchField} type="checkbox" name="field_authority_enabled" label={t_i18n('Enable field authority')} />
              <FieldArray name="field_authority_rules">
                {({ push, remove }) => (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                    {values.field_authority_rules.map((_, index) => (
                      <Box key={index} sx={{ border: `1px solid ${theme.palette.divider}`, borderRadius: 1, padding: 1.5 }} data-testid={`curation-authority-rule-${index}`}>
                        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 1, alignItems: 'end' }}>
                          <Field component={SelectFieldFds} name={`field_authority_rules.${index}.entity_type`} label={t_i18n('Entity type')} fullWidth={true}>
                            {knowledgeTypes.map((type) => <SelectItem key={type} value={type}>{t_i18n(`entity_${type}`)}</SelectItem>)}
                          </Field>
                          <Field component={TextField} variant="standard" name={`field_authority_rules.${index}.attribute`} label={t_i18n('Attribute')} fullWidth={true} />
                          <IconButton size="small" aria-label={t_i18n('Delete')} title={t_i18n('Delete')} onClick={() => remove(index)}>
                            <DeleteOutlined fontSize="small" />
                          </IconButton>
                        </Box>
                        <Box sx={{ marginTop: 1 }}>
                          <CurationAuthoritySourcesField name={`field_authority_rules.${index}.sources`} connectors={connectorOptions} />
                        </Box>
                      </Box>
                    ))}
                    <Button size="small" variant="tertiary" onClick={() => push({ entity_type: '', attribute: '', sources: [] })}>
                      {t_i18n('Add a field authority rule')}
                    </Button>
                  </Box>
                )}
              </FieldArray>
            </Card>
          </Box>
        </Form>
      )}
    </Formik>
  );
};

const CurationSettings = () => {
  const { curationSettings } = useLazyLoadQuery<CurationSettingsQuery>(curationSettingsQuery, {}, { fetchPolicy: 'store-and-network' });
  return (
    <div data-testid="curation-settings-page">
      <CurationSettingsForm settings={curationSettings} />
    </div>
  );
};

export default CurationSettings;
