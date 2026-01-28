import React from 'react';
import { Field, FieldArray } from 'formik';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../components/i18n';
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
                size="default"
                color="secondary"
                aria-label="Add"
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
                  marginTop: 10,
                }}
              >
                <Field
                  component={TextField}
                  variant="standard"
                  required
                  onSubmit={() => updateField('redirect_uris', form.values.redirect_uris)}
                  name={`redirect_uris[${index}]`}
                  label={t_i18n('Redirect url value')}
                  fullWidth
                />
                {index !== 0 && (
                  <IconButton
                    size="default"
                    color="primary"
                    aria-label={t_i18n('Delete')}
                    style={{ marginTop: 10 }}
                    onClick={() => {
                      const redirectUris = [...form.values.redirect_uris];
                      if (redirectUris.length === 1) return;
                      redirectUris.splice(index, 1);
                      remove(index);
                      updateField('redirect_uris', redirectUris);
                    }} // Delete
                  >
                    <Delete fontSize="small" />
                  </IconButton>
                )}
              </div>
            ))}
          </>
        )}
      </FieldArray>
    </>
  );
};

export default OpenIDConfig;
