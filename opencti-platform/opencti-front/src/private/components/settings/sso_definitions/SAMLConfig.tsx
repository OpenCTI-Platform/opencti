import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';

const SAMLConfig = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="issuer"
        label={t_i18n('SAML Entity ID/Issuer')}
        required
        fullWidth
        style={{ marginTop: 10 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="callbackUrl"
        label={t_i18n('SAML Callback URL')}
        fullWidth
        required
        style={{ marginTop: 10 }}
      />
      <Field
        id="filled-multiline-flexible"
        component={TextField}
        variant="standard"
        name="idpCert"
        label={t_i18n('Identity Provider Encryption Certificate')}
        required
        fullWidth
        multiline
        rows={4}
        style={{ marginTop: 10 }}
      />
      <Field
        id="filled-multiline-flexible"
        component={TextField}
        variant="standard"
        name="entryPoint"
        label={t_i18n('Entry point')}
        required
        fullWidth
        multiline
        rows={4}
        style={{ marginTop: 10 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="privateKey"
        label={t_i18n('Private key')}
        fullWidth
        style={{ marginTop: 10 }}
        type="password"
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="wantAssertionsSigned"
        label={t_i18n('Want assertion signed')}
        containerstyle={{ marginLeft: 2, marginTop: 10 }}
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="wantAuthnResponseSigned"
        label={t_i18n('Requires SAML responses to be signed')}
        containerstyle={{ marginLeft: 2 }}
      />
      <div style={{ marginTop: 40, marginBottom: 10 }}>
        <Typography variant="h2">Identity Provider Information</Typography>
        <Field
          component={SwitchField}
          variant="standard"
          type="checkbox"
          name="loginIdpDirectly"
          label={t_i18n('Allow login from identity provider directly')}
          containerstyle={{ marginLeft: 2 }}
        />
        <Field
          component={SwitchField}
          variant="standard"
          type="checkbox"
          name="logoutRemote"
          label={t_i18n('Allow logout from Identity provider directly')}
          containerstyle={{ marginLeft: 2 }}
        />
      </div>
      <Field
        component={SelectField}
        variant="standard"
        name="providerMethod"
        label={t_i18n('Method of Provider metadata')}
        fullWidth
        containerstyle={{ width: '100%' }}
      >
        <MenuItem value="Manual">Manual</MenuItem>
        <MenuItem value="Upload">Upload</MenuItem>
      </Field>
      <Field
        id="filled-multiline-flexible"
        component={TextField}
        variant="standard"
        name="signingCert"
        label={t_i18n('Identity Provider Signing Certificate')}
        fullWidth
        multiline
        rows={4}
        style={{ marginTop: 10 }}
      />
      <Field
        component={SelectField}
        variant="standard"
        name="ssoBindingType"
        label={t_i18n('SSO Binding type')}
        fullWidth
        containerstyle={{ width: '100%', marginBottom: 20, marginTop: 10 }}
      >
        <MenuItem value="Redirect">Redirect</MenuItem>
        <MenuItem value="Post">Post</MenuItem>
      </Field>
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="forceReauthentication"
        label={t_i18n('Force re-authentication even if user has valid SSO session')}
        containerstyle={{ marginLeft: 2 }}
      />
    </>
  );
};

export default SAMLConfig;
