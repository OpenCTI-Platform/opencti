import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { Button } from '@mui/material';
import { TextField } from 'formik-mui';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import SwitchField from '../../../../components/fields/SwitchField';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';

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
            component={TextField}
            variant="standard"
            name="name"
            label={t_i18n('Authentication Name')}
            fullWidth
            style={{ marginTop: 20 }}
          />
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
            name="private"
            label={t_i18n('Private key')}
            fullWidth
            style={{ marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="assertion"
            defaultValue={true}
            label={t_i18n('Want assertion signed')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="responses"
            defaultValue={true}
            label={t_i18n('Requires SAML responses to be signed')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <div>Identity Provider Information</div>
          <Field
            component={SwitchField}
            variant="standard"
            name="login"
            defaultValue={true}
            label={t_i18n('Allow login from identity provider directly')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={SwitchField}
            variant="standard"
            name="responses"
            defaultValue={true}
            label={t_i18n('Allow logout from Identity provider directly')}
            containerstyle={{ marginLeft: 2, marginTop: 20 }}
          />
          <Field
            component={SelectField}
            variant="standard"
            name="entityId"
            label={t_i18n('How to provide Provider metadata')}
            fullWidth
            containerstyle={{ width: '100%' }}
          >
            <MenuItem value="Manual">Manual</MenuItem>
            <MenuItem value="Upload">Upload</MenuItem>
          </Field>
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
          <Field
            id="filled-multiline-flexible"
            component={TextField}
            variant="standard"
            name="entityId"
            label={t_i18n('Identity Provider Signing Certificate')}
            fullWidth
            multiline
            rows={4}
            style={{ marginTop: 20 }}
          />
          <Field
            id="filled-multiline-flexible"
            component={TextField}
            variant="standard"
            name="entityId"
            label={t_i18n('Identity Provider Encryption Certificate')}
            fullWidth
            multiline
            rows={4}
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
