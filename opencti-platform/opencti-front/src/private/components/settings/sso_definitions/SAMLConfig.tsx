import React from 'react';
import { Field } from 'formik';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import Typography from '@mui/material/Typography';
import SwitchField from '../../../../components/fields/SwitchField';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import TextField from '../../../../components/TextField';

interface Props {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}
const SAMLConfig = ({ updateField }: Props) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="issuer"
        label={t_i18n('SAML Entity ID/Issuer')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 10 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="callbackUrl"
        label={t_i18n('SAML Callback URL')}
        onSubmit={updateField}
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
        onSubmit={updateField}
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
        onSubmit={updateField}
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
        onSubmit={updateField}
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
        onChange={updateField}
        containerstyle={{ marginLeft: 2, marginTop: 10 }}
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="wantAuthnResponseSigned"
        label={t_i18n('Requires SAML responses to be signed')}
        onChange={updateField}
        containerstyle={{ marginLeft: 2 }}
      />
      <div style={{ marginTop: 40, marginBottom: 10 }}>
        <Typography variant="h2">Identity Provider Information</Typography>
        <Field
          component={SwitchField}
          variant="standard"
          type="checkbox"
          name="loginIdpDirectly"
          onChange={updateField}
          label={t_i18n('Allow login from identity provider directly')}
          containerstyle={{ marginLeft: 2 }}
        />
        <Field
          component={SwitchField}
          variant="standard"
          type="checkbox"
          name="logoutRemote"
          onChange={updateField}
          label={t_i18n('Allow logout from Identity provider directly')}
          containerstyle={{ marginLeft: 2 }}
        />
      </div>
      <Field
        component={SelectField}
        variant="standard"
        name="providerMethod"
        label={t_i18n('Method of Provider metadata')}
        onSubmit={updateField}
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
        onSubmit={updateField}
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
        onSubmit={updateField}
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
        onChange={updateField}
        containerstyle={{ marginLeft: 2 }}
      />
      {/* <Field */}
      {/*  component={SwitchField} */}
      {/*  variant="standard" */}
      {/*  type="checkbox" */}
      {/*  name="enableDebugMode" */}
      {/*  label={t_i18n('Enable debug mode to troubleshoot for this authentication')} */}
      {/*  onChange={updateField} */}
      {/*  containerstyle={{ marginLeft: 2 }} */}
      {/* /> */}
    </>
  );
};

export default SAMLConfig;
