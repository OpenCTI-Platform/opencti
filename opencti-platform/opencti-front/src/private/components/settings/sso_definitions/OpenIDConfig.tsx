import React from 'react';
import { Field, FieldArray } from 'formik';
import { IconButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import SelectField from '../../../../components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import { Add, Delete } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
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
      <FieldArray name="redirect_uris">
        {({ push, remove, form }) => (
          <>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                marginTop: 20,
              }}
            >
              <Typography variant="h2">{t_i18n('Add redirect uris')}</Typography>
              <IconButton
                color="secondary"
                aria-label="Add"
                size="large"
                style={{ marginBottom: 8 }}
                onClick={() => push('')}
              >
                <Add fontSize="small" />
              </IconButton>
            </div>
            {form.values.redirect_uris && form.values.redirect_uris.map((value: string, index: number) => (
              <div
                key={index}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: 8,
                }}
              >
                <Field
                  component={TextField}
                  variant="standard"
                  onSubmit={() => updateField('redirect_uris', form.values.redirect_uris)}
                  name={`redirect_uris[${index}]`}
                  label={t_i18n('Redirect url value')}
                  fullWidth
                  style={{ marginTop: 20 }}
                />
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Delete')}
                  style={{ marginTop: 10 }}
                  onClick={() => {
                    remove(index);
                    const redirectUris = [...form.values.redirect_uris];
                    redirectUris.splice(index, 1);
                    updateField('redirect_uris', redirectUris);
                  }} // Delete
                >
                  <Delete fontSize="small" />
                </IconButton>
              </div>
            ))}
          </>
        )}
      </FieldArray>
      <FieldArray name="advancedConfigurations">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <Typography variant="h2">{t_i18n('Add more fields')}</Typography>
              <IconButton
                color="secondary"
                aria-label="Add"
                size="large"
                style={{ marginBottom: 8 }}
                onClick={() => push({ key: '', value: '', type: 'String' })}
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
                      onSubmit={() => updateField('advancedConfigurations', form.values.advancedConfigurations)}
                      name={`advancedConfigurations[${index}].key`}
                      label={t_i18n('Key (in passport)')}
                      containerstyle={{ width: '20%' }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      onSubmit={() => updateField('advancedConfigurations', form.values.advancedConfigurations)}
                      name={`advancedConfigurations[${index}].value`}
                      label={t_i18n('Value (in IDP)')}
                      containerstyle={{ width: '20%' }}
                    />
                    <Field
                      component={SelectField}
                      variant="standard"
                      onSubmit={() => updateField('advancedConfigurations', form.values.advancedConfigurations)}
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
                      onClick={() => {
                        remove(index);
                        const advancedConfigurations = [...form.values.advancedConfigurations];
                        advancedConfigurations.splice(index, 1);
                        updateField('advancedConfigurations', advancedConfigurations);
                      }} // Delete
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

export default OpenIDConfig;
