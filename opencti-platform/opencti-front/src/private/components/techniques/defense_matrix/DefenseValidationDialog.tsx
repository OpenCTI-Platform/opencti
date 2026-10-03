import React from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { DialogActions, Typography } from '@mui/material';
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
import type { DefenseThreatOption } from './defenseMatrix-utils';
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

interface DefenseValidationDialogProps {
  open: boolean;
  onClose: () => void;
  onValidated?: () => void;
  techniques: ReadonlyArray<DefenseValidationTechnique>;
  platformIds: ReadonlyArray<string>;
  threats: ReadonlyArray<DefenseThreatOption>;
}

const DefenseValidationDialog = ({ open, onClose, onValidated, techniques, platformIds, threats }: DefenseValidationDialogProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commit] = useApiMutation<DefenseValidationDialogMutation>(defenseValidationDialogMutation, undefined, {
    successMessage: t_i18n('Validation requested in OpenAEV'),
  });
  const validationSchema = Yup.object().shape({
    name: Yup.string().trim().max(250),
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
          platformIds: [...platformIds],
          threatId: values.threatId === NO_THREAT ? null : values.threatId,
          name: name.length > 0 ? name : null,
          periodicity: values.periodicity,
          duration: values.duration,
          type_affinity: values.type_affinity,
          platforms_affinity: values.platforms_affinity,
        },
      },
      onCompleted: (response) => {
        setSubmitting(false);
        onValidated?.();
        onClose();
        const coverageId = response.defenseGapsValidate?.securityCoverage.id;
        if (coverageId) {
          navigate(`/dashboard/analyses/security_coverages/${coverageId}`);
        }
      },
      onError: () => setSubmitting(false),
    });
  };

  return (
    <Dialog open={open} onClose={onClose} title={t_i18n('Validate with OpenAEV')} size="medium">
      <Formik<DefenseValidationFormValues> initialValues={initialValues} validationSchema={validationSchema} onSubmit={onSubmit} enableReinitialize>
        {({ isSubmitting, setFieldValue, submitForm }) => (
          <Form data-testid="defense-validation-form">
            <Typography variant="body2">
              {t_i18n('A security coverage will be created for the selected techniques. OpenAEV generates a scenario restricted to these techniques and sends back its results, which update the validation layer.')}
            </Typography>
            <Typography variant="body2" sx={{ marginTop: 1 }} data-testid="defense-validation-techniques">
              {techniques.map((technique) => (technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name)).join(', ')}
            </Typography>
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
                {t_i18n('Validate')}
              </Button>
            </DialogActions>
          </Form>
        )}
      </Formik>
    </Dialog>
  );
};

export default DefenseValidationDialog;
