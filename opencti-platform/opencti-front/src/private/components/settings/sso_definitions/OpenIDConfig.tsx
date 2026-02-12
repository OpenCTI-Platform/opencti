import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import TextField from '../../../../components/TextField';

interface OpenIDConfigProps {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}

const OpenIDConfig = ({ updateField }: OpenIDConfigProps) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="client_id"
        required
        label={t_i18n('Client ID')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="client_secret"
        required
        label={t_i18n('Client Secret')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
        type="password"
      />
      <Field
        component={TextField}
        variant="standard"
        name="issuer"
        label={t_i18n('OpenID issuer')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="redirect_uri"
        label={t_i18n('Redirect url value')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
    </>
  );
};

export default OpenIDConfig;
