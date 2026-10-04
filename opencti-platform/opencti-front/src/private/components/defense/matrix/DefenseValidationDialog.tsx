import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Box, DialogActions, List, ListItem, Typography } from '@mui/material';
import { Chip } from '@filigran/design-system';
import { useNavigate } from 'react-router';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import OpenVocabField from '@components/common/form/OpenVocabField';
import TextField from '../../../../components/TextField';
import PeriodicityField from '../../../../components/fields/PeriodicityField';
import SelectFieldFds, { SelectItem } from '../../../../components/fields/SelectFieldFds';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { MESSAGING$ } from '../../../../relay/environment';
import type { DefenseThreatOption } from './defenseMatrix-utils';
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
  // Platforms every technique is validated on (matrix scope, technique drawer)
  platforms?: ReadonlyArray<DefenseValidationPlatform>;
  // Exact technique and platform pairs selected in the gap backlog
  gaps?: ReadonlyArray<DefenseValidationGap>;
  threats: ReadonlyArray<DefenseThreatOption>;
}

const techniqueTitle = (technique: DefenseValidationTechnique) => (technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name);

const DefenseValidationDialog = ({ open, onClose, onValidated, techniques, platforms = [], gaps = [], threats }: DefenseValidationDialogProps) => {
  const { t_i18n } = useFormatter();
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
            <Box
              component="section"
              aria-label={t_i18n('What will be validated')}
              sx={{ marginTop: 2, padding: 1.5, borderRadius: 1, border: 1, borderColor: 'divider' }}
              data-testid="defense-validation-preview"
            >
              <Typography variant="h4" gutterBottom>{t_i18n('What will be validated')}</Typography>
              <List dense disablePadding data-testid="defense-validation-techniques">
                {techniques.map((technique) => {
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
              <Typography variant="body2" color="text.secondary" sx={{ marginTop: 1 }} data-testid="defense-validation-scenario">
                {t_i18n('Scenario: {type} targets on {platforms}, threat emulated: {threat}', {
                  values: {
                    type: t_i18n(values.type_affinity === 'ENDPOINT' ? 'Endpoint' : values.type_affinity),
                    platforms: values.platforms_affinity.length > 0 ? values.platforms_affinity.join(', ') : t_i18n('any platform'),
                    threat: threats.find((threat) => threat.value === values.threatId)?.label ?? t_i18n('None'),
                  },
                })}
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
            <PeriodicityField
              name="duration"
              label={t_i18n('Duration')}
              style={fieldSpacingContainerStyle}
              setFieldValue={setFieldValue}
            />
            <Field
              component={SelectFieldFds}
              variant="outlined"
              name="type_affinity"
              label={t_i18n('Type affinity')}
              fullWidth
              onChange={(name: string, value: string) => setFieldValue(name, value)}
              containerstyle={fieldSpacingContainerStyle}
            >
              <SelectItem value="ENDPOINT">{t_i18n('Endpoint')}</SelectItem>
            </Field>
            <OpenVocabField
              label={t_i18n('Platform(s) affinity')}
              type="platforms_ov"
              name="platforms_affinity"
              onChange={(name, value) => setFieldValue(name, value)}
              containerStyle={fieldSpacingContainerStyle}
              multiple
            />
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
