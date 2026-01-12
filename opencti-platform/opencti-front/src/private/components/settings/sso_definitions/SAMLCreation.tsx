import React from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import { Add, Delete } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import SwitchField from '../../../../components/fields/SwitchField';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import TextField from '../../../../components/TextField';
interface Props {
  updateField: (field: keyof SSODefinitionFormValues, value: unknown) => void;
}
const SAMLCreation = ({ updateField }: Props) => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={TextField}
        variant="standard"
        name="privateKey"
        label={t_i18n('Private key')}
        onSubmit={updateField}
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="wantAssertionsSigned"
        label={t_i18n('Want assertion signed')}
        onSubmit={updateField}
        containerstyle={{ marginLeft: 2, marginTop: 20 }}
      />
      <Field
        component={SwitchField}
        variant="standard"
        type="checkbox"
        name="wantAuthnResponseSigned"
        label={t_i18n('Requires SAML responses to be signed')}
        onSubmit={updateField}
        containerstyle={{ marginLeft: 2 }}
      />
      <div style={{ marginTop: 40, marginBottom: 20 }}>
        <Typography variant="h2">Identity Provider Information</Typography>
        <Field
          component={SwitchField}
          variant="standard"
          type="checkbox"
          name="loginIdpDirectly"
          onSubmit={updateField}
          label={t_i18n('Allow login from identity provider directly')}
          containerstyle={{ marginLeft: 2 }}
        />
        <Field
          component={SwitchField}
          variant="standard"
          type="checkbox"
          name="logoutRemote"
          onSubmit={updateField}
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
        component={TextField}
        variant="standard"
        name="issuer"
        label={t_i18n('SAML Entity ID/Issuer')}
        onSubmit={updateField}
        required
        fullWidth
        style={{ marginTop: 20 }}
      />
      <Field
        component={TextField}
        variant="standard"
        name="callbackUrl"
        label={t_i18n('SAML SSO URL')}
        onSubmit={updateField}
        fullWidth
        required
        style={{ marginTop: 20 }}
      />
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
        style={{ marginTop: 20 }}
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
        style={{ marginTop: 20 }}
      />
      <Field
        component={SelectField}
        variant="standard"
        name="ssoBindingType"
        label={t_i18n('SSO Binding type')}
        onSubmit={updateField}
        fullWidth
        containerstyle={{ width: '100%' }}
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
        onSubmit={updateField}
        containerstyle={{ marginLeft: 2 }}
      />

      <FieldArray name="advancedConfigurations">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <Typography variant="h2">Add more fields</Typography>
              <IconButton
                color="secondary"
                aria-label="Add"
                size="large"
                style={{ marginBottom: 12 }}
                onClick={() =>
                  push({ key: '', value: '', type: 'String' })
                }
              >
                <Add fontSize="small" />
              </IconButton>
            </div>
            {form.values.advancedConfigurations
              && form.values.advancedConfigurations.map(
                (
                  conf: { key: string; value: string; type: string },
                  index: number,
                ) => (
                  <div
                    key={index}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-around',
                      marginBottom: 8,
                    }}
                  >
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`advancedConfigurations[${index}].key`}
                      label={t_i18n('Key (in passport)')}
                      containerstyle={{ width: '20%' }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name={`advancedConfigurations[${index}].value`}
                      label={t_i18n('Value (in IDP)')}
                      containerstyle={{ width: '20%' }}
                    />
                    <Field
                      component={SelectField}
                      variant="standard"
                      name={`advancedConfigurations[${index}].type`}
                      label={t_i18n('Field type')}
                      containerstyle={{ width: '20%' }}
                    >
                      <MenuItem value="Boolean">Boolean</MenuItem>
                      <MenuItem value="Integer">Integer</MenuItem>
                      <MenuItem value="String">String</MenuItem>
                      <MenuItem value="Array">Array</MenuItem>
                    </Field>
                    <IconButton
                      color="primary"
                      aria-label={t_i18n('Delete')}
                      style={{ marginTop: 10 }}
                      onClick={() => remove(index)} // Delete
                    >
                      <Delete fontSize="small" />
                    </IconButton>
                  </div>
                ),
              )}
          </>
        )}
      </FieldArray>
    </>
  );
};

export default SAMLCreation;
