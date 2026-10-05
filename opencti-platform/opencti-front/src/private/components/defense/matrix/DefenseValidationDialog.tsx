import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Box, DialogActions, List, ListItem, Stack, Typography } from '@mui/material';
import {
  Chip,
  Combobox,
  ComboboxChips,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import { useIntl } from 'react-intl';
import { Link, useNavigate } from 'react-router';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { PATH_DEFENSE_GAPS } from '@components/common/routes/paths';
import Alert from '../../../../components/Alert';
import TextField from '../../../../components/TextField';
import PeriodicityField from '../../../../components/fields/PeriodicityField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { MESSAGING$ } from '../../../../relay/environment';
import { type DefenseThreatOption, MAX_VALIDATION_TECHNIQUES } from './defenseMatrix-utils';
import { notifyPayloadErrors } from './defenseMutation-utils';
import { DefenseValidationDialogMutation } from './__generated__/DefenseValidationDialogMutation.graphql';

const defenseValidationDialogMutation = graphql`
  mutation DefenseValidationDialogMutation($input: DefenseValidationInput!) {
    defenseGapsValidate(input: $input) {
      gaps_count
      securityCoverage {
        id
        name
      }
      grouping {
        id
      }
    }
  }
`;

const NO_THREAT = 'none';
const DEFENSE_VALIDATION_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/defense-matrix/#validate-in-openaev';
// Techniques listed in the preview before the count of the others
const PREVIEW_TECHNIQUES = 6;

interface ScenarioPlatformOption {
  value: string;
  label: string;
}
// Endpoint platforms of the OpenAEV scenario, values of the platforms_ov vocabulary
const SCENARIO_PLATFORMS: ScenarioPlatformOption[] = [
  { value: 'windows', label: 'Windows' },
  { value: 'linux', label: 'Linux' },
  { value: 'macos', label: 'macOS' },
];
const scenarioPlatformLabel = (value: string) => SCENARIO_PLATFORMS.find((platform) => platform.value === value)?.label ?? value;

interface DefenseValidationFormValues {
  name: string;
  threatId: string;
  periodicity: string;
  duration: string;
  type_affinity: string;
  platforms_affinity: string[];
}

export interface DefenseValidationTechnique {
  id: string;
  name: string;
  x_mitre_id?: string | null;
}

export interface DefenseValidationPlatform {
  id: string;
  name: string;
}

export interface DefenseValidationGap {
  attackPatternId: string;
  platformId: string;
  platformName: string;
}

interface DefenseValidationDialogProps {
  open: boolean;
  onClose: () => void;
  onValidated?: () => void;
  techniques: ReadonlyArray<DefenseValidationTechnique>;
  // Techniques of the scope left out because a request holds at most MAX_VALIDATION_TECHNIQUES
  deferredCount?: number;
  // Platforms every technique is validated on (matrix scope, technique drawer)
  platforms?: ReadonlyArray<DefenseValidationPlatform>;
  // Exact technique and platform pairs selected in the gap backlog
  gaps?: ReadonlyArray<DefenseValidationGap>;
  threats: ReadonlyArray<DefenseThreatOption>;
}

const techniqueTitle = (technique: DefenseValidationTechnique) => (technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name);

const DefenseValidationDialog = ({ open, onClose, onValidated, techniques, deferredCount = 0, platforms = [], gaps = [], threats }: DefenseValidationDialogProps) => {
  const { t_i18n } = useFormatter();
  const intl = useIntl();
  const platformsOf = (techniqueId: string): string[] => {
    const paired = gaps.filter((gap) => gap.attackPatternId === techniqueId).map((gap) => gap.platformName);
    return Array.from(new Set([...paired, ...platforms.map((platform) => platform.name)]));
  };
  const navigate = useNavigate();
  const [commit] = useApiMutation<DefenseValidationDialogMutation>(defenseValidationDialogMutation);
  const validationSchema = Yup.object().shape({
    // Optional: an empty name lets the platform generate one
    name: Yup.string().trim().transform((value) => (value === '' ? undefined : value))
      .min(2, t_i18n('Name must be at least 2 characters'))
      .max(250),
    periodicity: Yup.string().required(t_i18n('This field is required')),
    duration: Yup.string().required(t_i18n('This field is required')),
  });
  const initialValues: DefenseValidationFormValues = {
    name: '',
    threatId: threats.length === 1 ? threats[0].value : NO_THREAT,
    periodicity: 'P1D',
    duration: 'P30D',
    type_affinity: 'ENDPOINT',
    platforms_affinity: ['windows', 'linux', 'macos'],
  };

  const onSubmit = (values: DefenseValidationFormValues, { setSubmitting }: { setSubmitting: (flag: boolean) => void }) => {
    const name = values.name.trim();
    commit({
      variables: {
        input: {
          attackPatternIds: techniques.map((technique) => technique.id),
          platformIds: platforms.map((platform) => platform.id),
          gaps: gaps.map((gap) => ({ attackPatternId: gap.attackPatternId, platformId: gap.platformId })),
          threatId: values.threatId === NO_THREAT ? null : values.threatId,
          name: name.length > 0 ? name : null,
          periodicity: values.periodicity,
          duration: values.duration,
          type_affinity: values.type_affinity,
          platforms_affinity: values.platforms_affinity,
        },
      },
      onCompleted: (response, errors) => {
        setSubmitting(false);
        if (notifyPayloadErrors(errors) || !response.defenseGapsValidate) return;
        MESSAGING$.notifySuccess(t_i18n('Validation requested in OpenAEV'));
        onValidated?.();
        onClose();
        const coverageId = response.defenseGapsValidate.securityCoverage.id;
        if (coverageId) {
          navigate(`/dashboard/analyses/security_coverages/${coverageId}`);
        }
      },
      onError: () => setSubmitting(false),
    });
  };

  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Validate in OpenAEV')} size="medium">
      <Formik<DefenseValidationFormValues> initialValues={initialValues} validationSchema={validationSchema} onSubmit={onSubmit} enableReinitialize>
        {({ isSubmitting, setFieldValue, submitForm, values }) => (
          <Form data-testid="defense-validation-form">
            <Typography variant="body2">
              {t_i18n('A security coverage will be created for the selected techniques. OpenAEV generates a scenario restricted to these techniques and sends back its results, which update the validation layer.')}
            </Typography>
            <Box sx={{ marginTop: 2 }} data-testid="defense-validation-setup">
              <Alert
                severity="info"
                content={(
                  <>
                    {t_i18n('Validation needs an OpenAEV platform that reads the security coverages of this platform through its collector. The OpenCTI account of that collector needs the Connector role.')}
                    {' '}
                    <a href={DEFENSE_VALIDATION_DOCUMENTATION_URL} target="_blank" rel="noreferrer">{t_i18n('How to connect OpenAEV')}</a>
                  </>
                )}
              />
            </Box>
            <Box
              component="section"
              aria-label={t_i18n('What will be validated')}
              sx={{ marginTop: 2, padding: 1.5, borderRadius: 1, border: 1, borderColor: 'divider' }}
              data-testid="defense-validation-preview"
            >
              <Stack direction="row" spacing={1} alignItems="baseline" sx={{ marginBottom: 1 }}>
                <Typography variant="h4" sx={{ margin: 0 }}>{t_i18n('What will be validated')}</Typography>
                <Typography variant="body2" color="text.secondary" data-testid="defense-validation-count">
                  {t_i18n('{count, plural, one {# technique} other {# techniques}}', { values: { count: techniques.length } })}
                </Typography>
              </Stack>
              <List dense disablePadding data-testid="defense-validation-techniques">
                {techniques.slice(0, PREVIEW_TECHNIQUES).map((technique) => {
                  const targets = platformsOf(technique.id);
                  return (
                    <ListItem key={technique.id} disableGutters sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      <Typography variant="body2" sx={{ marginRight: 1 }}>{techniqueTitle(technique)}</Typography>
                      {targets.length === 0
                        ? <Chip label={t_i18n('Every security platform')} />
                        : targets.map((name) => <Chip key={name} label={name} />)}
                    </ListItem>
                  );
                })}
              </List>
              {techniques.length > PREVIEW_TECHNIQUES && (
                <Typography variant="body2" color="text.secondary" data-testid="defense-validation-more">
                  {t_i18n('{count, plural, one {and # more technique} other {and # more techniques}}', { values: { count: techniques.length - PREVIEW_TECHNIQUES } })}
                </Typography>
              )}
              {deferredCount > 0 && (
                <Box sx={{ marginTop: 1 }} data-testid="defense-validation-deferred">
                  <Alert
                    severity="warning"
                    content={(
                      <>
                        {t_i18n('{count, plural, one {# more technique of this scope is not part of this request.} other {# more techniques of this scope are not part of this request.}}', { values: { count: deferredCount } })}
                        {' '}
                        {t_i18n('A validation request holds at most {max} techniques, the ones used by the most threats first. Select the others in the Gaps tab to validate them.', { values: { max: MAX_VALIDATION_TECHNIQUES } })}
                        {' '}
                        <Link to={PATH_DEFENSE_GAPS} onClick={onClose}>{t_i18n('Open the Gaps tab')}</Link>
                      </>
                    )}
                  />
                </Box>
              )}
              <Typography variant="body2" color="text.secondary" sx={{ marginTop: 1 }} data-testid="defense-validation-scenario">
                {(() => {
                  const scenarioValues = {
                    type: t_i18n('Endpoint'),
                    platforms: values.platforms_affinity.length > 0
                      ? intl.formatList(values.platforms_affinity.map(scenarioPlatformLabel), { type: 'conjunction' })
                      : t_i18n('any platform'),
                    threat: threats.find((threat) => threat.value === values.threatId)?.label ?? '',
                  };
                  return values.threatId === NO_THREAT || !scenarioValues.threat
                    ? t_i18n('Scenario: {type} targets on {platforms}, no threat emulated', { values: scenarioValues })
                    : t_i18n('Scenario: {type} targets on {platforms}, emulating {threat}', { values: scenarioValues });
                })()}
              </Typography>
            </Box>
            <Field
              component={TextField}
              variant="outlined"
              name="name"
              label={t_i18n('Name')}
              helperText={t_i18n('Leave empty to generate a name')}
              fullWidth
              style={fieldSpacingContainerStyle}
            />
            {threats.length > 0 && (
              <Field
                component={SelectFieldFds}
                variant="outlined"
                name="threatId"
                label={t_i18n('Threat to emulate')}
                helpertext={t_i18n('The threat the validation is for, recorded with the security coverage. OpenAEV tests the selected techniques either way.')}
                fullWidth
                onChange={(name: string, value: string) => setFieldValue(name, value)}
                containerstyle={fieldSpacingContainerStyle}
              >
                <SelectItem value={NO_THREAT}>{t_i18n('None')}</SelectItem>
                {threats.map((threat) => (
                  <SelectItem key={threat.value} value={threat.value}>{threat.label}</SelectItem>
                ))}
              </Field>
            )}
            <PeriodicityField
              name="periodicity"
              label={t_i18n('Coverage validity period')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <Typography variant="caption" color="text.secondary" component="p" sx={{ marginTop: 0.5 }}>
              {t_i18n('How often OpenAEV runs the scenario again, each run refreshing the validation results')}
            </Typography>
            <PeriodicityField
              name="duration"
              label={t_i18n('Duration')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <Typography variant="caption" color="text.secondary" component="p" sx={{ marginTop: 0.5 }}>
              {t_i18n('How long each run of the scenario lasts')}
            </Typography>
            <Field
              component={SelectFieldFds}
              variant="outlined"
              name="type_affinity"
              label={t_i18n('Type affinity')}
              helpertext={t_i18n('The kind of targets OpenAEV runs the scenario on, endpoints for now')}
              fullWidth
              onChange={(name: string, value: string) => setFieldValue(name, value)}
              containerstyle={fieldSpacingContainerStyle}
            >
              <SelectItem value="ENDPOINT">{t_i18n('Endpoint')}</SelectItem>
            </Field>
            <Box style={fieldSpacingContainerStyle}>
              <Combobox<ScenarioPlatformOption>
                multiple
                className="w-full"
                options={SCENARIO_PLATFORMS}
                value={SCENARIO_PLATFORMS.filter((platform) => values.platforms_affinity.includes(platform.value))}
                getOptionLabel={(option) => option.label}
                isOptionEqualToValue={(option, other) => option.value === other.value}
                onValueChange={(next) => setFieldValue('platforms_affinity', ((next as ScenarioPlatformOption[] | null) ?? []).map((option) => option.value))}
              >
                <ComboboxLabel>{t_i18n('Platform affinity')}</ComboboxLabel>
                <ComboboxField>
                  <ComboboxChips aria-label={t_i18n('Platform affinity')} />
                  <ComboboxInput
                    placeholder={values.platforms_affinity.length === 0 ? t_i18n('any platform') : undefined}
                    data-testid="defense-validation-platforms"
                  />
                  <ComboboxControls>
                    <ComboboxClear />
                    <ComboboxTrigger />
                  </ComboboxControls>
                </ComboboxField>
                <ComboboxContent emptyMessage={t_i18n('No results')} listAriaLabel={t_i18n('Platform affinity')} />
                <ComboboxHelperText>{t_i18n('The operating systems of the endpoints the scenario runs on, any of them when empty')}</ComboboxHelperText>
              </Combobox>
            </Box>
            <DialogActions sx={{ paddingX: 0, marginTop: 2 }}>
              <Button variant="secondary" onClick={onClose} disabled={isSubmitting}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={isSubmitting || techniques.length === 0} data-testid="defense-validation-submit">
                {t_i18n('{count, plural, one {Validate # technique} other {Validate # techniques}}', { values: { count: techniques.length } })}
              </Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default DefenseValidationDialog;
