import { useEffect } from 'react';
import { interval } from 'rxjs';
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
import EnterpriseEditionButton from '@components/common/entreprise_edition/EnterpriseEditionButton';
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
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import { THIRTY_SECONDS } from '../../../../utils/Time';
import CurationAuthoritySourcesField, { AuthoritySourceOption, toAuthoritySourceOption } from './CurationAuthoritySourcesField';
import { adjudicationAgentOptions, authorityAttributeOptions, missingAdjudicationPrerequisite } from './curationSettingsUtils';
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
    curationAdjudicationSetup {
      enterprise_edition
      xtm_one_configured
      agents {
        agent_slug
        agent_name
      }
    }
    curationAuthorityAttributes {
      entity_type
      attributes {
        name
        label
      }
    }
  }
`;

const CURATION_DOCUMENTATION = 'https://docs.opencti.io/latest/usage/knowledge-curation/';
const XTM_SUITE_DOCUMENTATION = 'https://docs.opencti.io/latest/deployment/configuration/#xtm-suite';
// The agent select cannot hold an empty value: this one stands for "no agent chosen", stored as null.
const HIGHEST_PRIORITY_AGENT = 'highest-priority-agent';

const LearnMore = ({ anchor }: { anchor: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 1 }}>
      <Button variant="tertiary" size="small" href={`${CURATION_DOCUMENTATION}#${anchor}`} target="_blank" rel="noreferrer">
        {t_i18n('Learn more')}
      </Button>
    </Box>
  );
};

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
type AdjudicationSetup = CurationSettingsQuery$data['curationAdjudicationSetup'];
type AuthorityAttributes = CurationSettingsQuery$data['curationAuthorityAttributes'];

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

interface CurationSettingsFormProps {
  settings: Settings;
  setup: AdjudicationSetup;
  authorityAttributes: AuthorityAttributes;
}

const CurationSettingsForm = ({ settings, setup, authorityAttributes }: CurationSettingsFormProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const labels = useCurationLabels();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [commitEdit] = useApiMutation<CurationSettingsEditMutation>(curationSettingsEditMutation);
  const [commitScan, scanning] = useApiMutation<CurationSettingsScanMutation>(curationScanMutation);
  // The scan request is written to the store by the mutation, and cleared by the manager once the scan ran: while it
  // is pending the settings are read again, so the page offers a new scan as soon as the previous one is done.
  const scanRequested = settings.force_scan;
  useEffect(() => {
    if (!scanRequested) return undefined;
    const subscription = interval(THIRTY_SECONDS).subscribe(() => {
      fetchQuery(curationSettingsQuery, {}).toPromise();
    });
    return () => subscription.unsubscribe();
  }, [scanRequested]);
  const typeOption = (type: string): FieldOption => ({ value: type, label: t_i18n(`entity_${type}`) });
  const detectorOption = (detector: string): FieldOption => ({ value: detector, label: labels.detector(detector) });
  // The curatable types, as the back end accepts them: domain objects except containers, and Indicator.
  const knowledgeTypes = authorityAttributes.map((entry) => entry.entity_type)
    .filter((type, index, all) => all.indexOf(type) === index)
    .sort((left, right) => t_i18n(`entity_${left}`).localeCompare(t_i18n(`entity_${right}`)));
  const connectorOptions = settings.authority_connector_sources.map((source) => toAuthoritySourceOption('connector', source.source_id, source.source_name, t_i18n('Connector')));
  const memberOption = (member: { id: string; name: string; entity_type: string }): FieldOption => ({ value: member.id, label: member.name, type: member.entity_type });
  const agentOptions = adjudicationAgentOptions(setup.agents, settings.adjudication_agent_slug);
  const attributesByType = new Map(authorityAttributes.map((entry) => [entry.entity_type, entry.attributes]));
  const attributeOptions = (entityType: string, current: string) => authorityAttributeOptions(attributesByType.get(entityType), current, t_i18n);
  const missingPrerequisite = missingAdjudicationPrerequisite(setup);
  const adjudicationMissing = () => {
    if (missingPrerequisite === 'enterprise_edition') return t_i18n('Adjudication needs the Enterprise Edition.');
    if (missingPrerequisite === 'xtm_one') return t_i18n('Adjudication needs a platform registered with XTM One.');
    return null;
  };

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
    adjudication_agent_slug: settings.adjudication_agent_slug || HIGHEST_PRIORITY_AGENT,
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
      // Without Enterprise Edition the switch is read-only: the stored preference is left untouched.
      ...(isEnterpriseEdition ? { adjudication_enabled: values.adjudication_enabled } : {}),
      adjudication_agent_slug: values.adjudication_agent_slug === HIGHEST_PRIORITY_AGENT ? null : values.adjudication_agent_slug,
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
        MESSAGING$.notifySuccess(t_i18n('A full curation scan will start at the next manager cycle'));
      },
    });
  };

  const dateOrNever = (date: string | null | undefined) => (date ? fldt(date) : t_i18n('Never'));

  return (
    <Formik<SettingsValues> initialValues={initialValues} validationSchema={validation} onSubmit={onSubmit} enableReinitialize>
      {({ submitForm, isSubmitting, values, dirty, setFieldValue }) => (
        <Form data-testid="curation-settings-form">
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, marginBottom: 2 }}>
            <Typography variant="body2" sx={{ flex: 1 }} color={theme.palette.text.light}>
              {t_i18n('Last scan: {scan} - last Knowledge health snapshot: {snapshot} - last weekly digest: {digest}', {
                values: { scan: dateOrNever(settings.last_scan_date), snapshot: dateOrNever(settings.last_snapshot_date), digest: dateOrNever(settings.last_digest_date) },
              })}
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
              <LearnMore anchor="when-detection-runs" />
              <Field
                component={SwitchField}
                type="checkbox"
                name="curation_enabled"
                label={t_i18n('Enable knowledge curation')}
                helpertext={t_i18n('Runs the detectors on every change and in a daily scan. On by default.')}
              />
              <Field
                component={ComboboxField}
                name="enabled_detectors"
                multiple={true}
                label={t_i18n('Enabled detectors')}
                helperText={t_i18n('The detectors that raise proposals, for example the name normalization. Empty: no detector runs.')}
                options={settings.available_detectors.map(detectorOption)}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={ComboboxField}
                name="curated_entity_types"
                multiple={true}
                label={t_i18n('Curated entity types')}
                helperText={t_i18n('The entity types the detectors examine. Indicators are always checked for staleness.')}
                options={knowledgeTypes.map(typeOption)}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="scan_max_entities_per_type"
                label={t_i18n('Maximum entities scanned per type')}
                helperText={t_i18n('Entities read per type at each daily scan, from 100 to 100,000 (5,000 by default).')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', marginTop: 2 }}>
                <Tag label={t_i18n('Vendor taxonomy {version} - {count} clusters', { values: { version: settings.taxonomy_version, count: settings.taxonomy_clusters_count } })} />
                {settings.graph_similarity_available && <Tag label={t_i18n('Graph similarity available')} />}
              </Box>
            </Card>
            <Card title={t_i18n('Thresholds')}>
              <LearnMore anchor="evidence-and-confidence" />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="similarity_threshold"
                label={t_i18n('Name similarity threshold (0.5 to 1)')}
                helperText={t_i18n('How close two names must be to pair two entities (0.8 by default).')}
                fullWidth={true}
              />
              <Field
                component={SwitchField}
                type="checkbox"
                name="description_similarity_enabled"
                label={t_i18n('Compare descriptions')}
                helpertext={t_i18n('Also compares the descriptions, which finds pairs whose names differ. Off by default.')}
                containerstyle={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="description_similarity_threshold"
                label={t_i18n('Description similarity threshold (0.5 to 1)')}
                helperText={t_i18n('How close two descriptions must be (0.92 by default).')}
                disabled={!values.description_similarity_enabled}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="behavior_threshold"
                label={t_i18n('Behavior overlap threshold (0.1 to 1)')}
                helperText={t_i18n('Share of ATT&CK techniques two entities must have in common to be paired (0.6 by default).')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="proposal_min_confidence"
                label={t_i18n('Minimum proposal confidence (0 to 1)')}
                helperText={t_i18n('Duplicate proposals below this confidence are not raised (0.45 by default).')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
              <Typography variant="body2" color={theme.palette.text.light} sx={{ marginTop: 2 }}>
                {t_i18n('Proposals in the ambiguous band are neither clearly right nor clearly wrong.')}
              </Typography>
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  type="number"
                  name="ambiguous_band_min"
                  label={t_i18n('Ambiguous band minimum')}
                  helperText={t_i18n('Included (0.55 by default).')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  type="number"
                  name="ambiguous_band_max"
                  label={t_i18n('Ambiguous band maximum')}
                  helperText={t_i18n('Excluded (0.85 by default).')}
                  fullWidth={true}
                  style={fieldSpacingContainerStyle}
                />
              </Box>
            </Card>
            <Card title={<Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>{t_i18n('Adjudication by the OpenCTI Curator')}<EEChip /></Box>}>
              <LearnMore anchor="ambiguous-band-and-adjudication-by-the-opencti-curator" />
              {adjudicationMissing() ? (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', marginBottom: 1 }} data-testid="curation-adjudication-missing">
                  <Typography variant="body2" color={theme.palette.text.light}>{adjudicationMissing()}</Typography>
                  {missingPrerequisite === 'enterprise_edition' ? (
                    <EnterpriseEditionButton inLine />
                  ) : (
                    <Button variant="tertiary" size="small" href={XTM_SUITE_DOCUMENTATION} target="_blank" rel="noreferrer">
                      {t_i18n('XTM Suite configuration')}
                    </Button>
                  )}
                </Box>
              ) : (
                <Typography variant="body2" color={theme.palette.text.light} sx={{ marginBottom: 1 }}>
                  {t_i18n('An XTM One agent judges the ambiguous band, the OpenCTI Curator by default.')}
                </Typography>
              )}
              <Field
                component={SwitchField}
                type="checkbox"
                name="adjudication_enabled"
                label={t_i18n('Enable adjudication')}
                helpertext={t_i18n('Sends up to 5 proposals of the ambiguous band per manager cycle. Off by default.')}
                disabled={!isEnterpriseEdition || !settings.adjudication_available}
              />
              <Field
                component={SelectFieldFds}
                name="adjudication_agent_slug"
                label={t_i18n('Agent')}
                helpertext={t_i18n('The XTM One agent that adjudicates (the OpenCTI Curator out of the box).')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                <SelectItem value={HIGHEST_PRIORITY_AGENT}>{t_i18n('The highest priority agent bound to curation adjudication')}</SelectItem>
                {agentOptions.map((agent) => <SelectItem key={agent.agent_slug} value={agent.agent_slug}>{agent.agent_name}</SelectItem>)}
              </Field>
              <ObjectMembersField
                name="adjudication_run_as"
                label={t_i18n('Run as (optional)')}
                helpertext={t_i18n('The OpenCTI account XTM One acts as (the platform administrator when empty).')}
                multiple={false}
                entityTypes={['User']}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="adjudication_daily_limit"
                label={t_i18n('Daily adjudication limit')}
                helperText={t_i18n('Proposals sent per UTC day, from 0 to 10,000 (50 by default). 0 stops adjudication.')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
            </Card>
            <Card title={t_i18n('Staleness, conflicts and merges')}>
              <LearnMore anchor="configure-curation" />
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="stale_default_months"
                label={t_i18n('Stale after (months, default)')}
                helperText={t_i18n('Months without activity before an entity is proposed as stale, from 1 to 240 (24 by default).')}
                fullWidth={true}
              />
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
                helpertext={t_i18n('What to do when sources give different procedures for a uses relationship.')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                {CURATION_RELATIONSHIP_CONFLICT_MODES.map((mode) => <SelectItem key={mode} value={mode}>{labels.conflictMode(mode)}</SelectItem>)}
              </Field>
              <Field
                component={TextField}
                variant="standard"
                type="number"
                name="merge_record_retention_days"
                label={t_i18n('Merges stay reversible for (days)')}
                helperText={t_i18n('How long a merge can be undone from its merge record, from 1 to 3,650 days (365 by default).')}
                fullWidth={true}
                style={fieldSpacingContainerStyle}
              />
            </Card>
            <Card title={t_i18n('Knowledge health weekly digest')}>
              <LearnMore anchor="weekly-digest" />
              <Field
                component={SwitchField}
                type="checkbox"
                name="digest_enabled"
                label={t_i18n('Send the weekly digest')}
                helpertext={t_i18n('Sends the latest Knowledge health snapshot to the recipients. Off by default.')}
              />
              <Field
                component={SelectFieldFds}
                name="digest_day"
                label={t_i18n('Day of the week (UTC)')}
                helpertext={t_i18n('The day the digest is sent, at most once every six days (Monday by default).')}
                fullWidth={true}
                containerstyle={fieldSpacingContainerStyle}
              >
                {CURATION_WEEK_DAYS.map((day) => <SelectItem key={day} value={String(day)}>{labels.weekDay(day)}</SelectItem>)}
              </Field>
              <ObjectMembersField
                name="digest_recipients"
                label={t_i18n('Recipients (users, groups or organizations)')}
                helpertext={t_i18n('Who receives it. Empty: nobody.')}
                multiple={true}
                style={fieldSpacingContainerStyle}
              />
            </Card>
            <Card title={t_i18n('Field authority')}>
              <LearnMore anchor="field-authority" />
              <Typography variant="body2" color={theme.palette.text.light} sx={{ marginBottom: 1 }}>
                {t_i18n('On a ruled attribute, the more authoritative source wins, whatever the confidence.')}
              </Typography>
              <Field
                component={SwitchField}
                type="checkbox"
                name="field_authority_enabled"
                label={t_i18n('Enable field authority')}
                helpertext={t_i18n('Applies the rules below when incoming data updates an existing entity. Off by default.')}
              />
              <FieldArray name="field_authority_rules">
                {({ push, remove }) => (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                    {values.field_authority_rules.map((rule, index) => (
                      <Box key={index} sx={{ border: `1px solid ${theme.palette.divider}`, borderRadius: 1, padding: 1.5 }} data-testid={`curation-authority-rule-${index}`}>
                        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 1, alignItems: 'end' }}>
                          <Field
                            component={SelectFieldFds}
                            name={`field_authority_rules.${index}.entity_type`}
                            label={t_i18n('Entity type')}
                            fullWidth={true}
                            onChange={() => setFieldValue(`field_authority_rules.${index}.attribute`, '')}
                          >
                            {knowledgeTypes.map((type) => <SelectItem key={type} value={type}>{t_i18n(`entity_${type}`)}</SelectItem>)}
                          </Field>
                          <Field
                            component={SelectFieldFds}
                            name={`field_authority_rules.${index}.attribute`}
                            label={t_i18n('Attribute')}
                            placeholder={rule.entity_type ? t_i18n('Choose an attribute') : t_i18n('Choose the entity type first')}
                            disabled={!rule.entity_type}
                            fullWidth={true}
                          >
                            {attributeOptions(rule.entity_type, rule.attribute).map((attribute) => (
                              <SelectItem key={attribute.name} value={attribute.name}>{attribute.label}</SelectItem>
                            ))}
                          </Field>
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
  const { curationSettings, curationAdjudicationSetup, curationAuthorityAttributes } = useLazyLoadQuery<CurationSettingsQuery>(
    curationSettingsQuery,
    {},
    { fetchPolicy: 'store-and-network' },
  );
  return (
    <div data-testid="curation-settings-page">
      <CurationSettingsForm settings={curationSettings} setup={curationAdjudicationSetup} authorityAttributes={curationAuthorityAttributes} />
    </div>
  );
};

export default CurationSettings;
