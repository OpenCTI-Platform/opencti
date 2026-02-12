import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';

const OpenIDConfig = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="client_id"
        required
        label={t_i18n('Client ID')}
        fullWidth
        style={{ marginBottom: 16 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="client_secret"
        required
        label={t_i18n('Client Secret')}
        fullWidth
        style={{ marginBottom: 16 }}
        type="password"
      />
      <Field
        component={TextField}
        variant="standard"
        name="issuer"
        required
        label={t_i18n('OpenID issuer')}
        fullWidth
        style={{ marginbottom: 16 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="redirect_uri"
        label={t_i18n('Redirect url value')}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
    </>
  );
};

export default OpenIDConfig;
