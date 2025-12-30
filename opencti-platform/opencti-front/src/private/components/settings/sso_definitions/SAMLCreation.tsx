import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Button } from '@mui/material';
import { TextField } from 'formik-mui';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';

export interface SAMLCreationValues {
  name: string;
  enabled: boolean;
  entityId: string;
  ssoUrl: string;
}

interface SAMLCreationProps {
  initialValues?: Partial<SAMLCreationValues>;
  onSubmit: (values: SAMLCreationValues, helpers: { setSubmitting: (b: boolean) => void; resetForm: () => void }) => void;
  onCancel: () => void;
}

const SAMLCreation: FunctionComponent<SAMLCreationProps> = ({
  initialValues,
  onSubmit,
  onCancel,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    entityId: Yup.string().required(t_i18n('This field is required')),
    ssoUrl: Yup.string().url(t_i18n('Must be a valid URL')).required(t_i18n('This field is required')),
  });

  const defaultValues: SAMLCreationValues = {
    name: '',
    enabled: true,
    entityId: '',
    ssoUrl: '',
  };

  const mergedInitialValues: SAMLCreationValues = {
    ...defaultValues,
    ...initialValues,
  };

  return (
    <Formik
      initialValues={mergedInitialValues}
      validationSchema={validationSchema}
      onSubmit={(values, helpers) => onSubmit(values, helpers)}
      onReset={onCancel}
    >
      {({ submitForm, handleReset, isSubmitting }) => (
        <Form>
          <Field
            component={SwitchField}
            variant="standard"
            name="enabled"
            defaultValue={true}
            label={t_i18n('Enable SAML authentication')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Name')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="entityId"
            label={t_i18n('SAML Entity ID')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={TextField}
            variant="standard"
            name="ssoUrl"
            label={t_i18n('SAML SSO URL')}
            fullWidth
            style={{ marginTop: 20 }}
          />

          <div
            style={{
              marginTop: 20,
              textAlign: 'right',
            }}
          >
            <Button
              variant="contained"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              variant="contained"
              color="secondary"
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(2) }}
            >
              {t_i18n('Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default SAMLCreation;
