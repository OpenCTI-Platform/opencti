import React from 'react';
import { Field, FieldArray } from 'formik';
import Typography from '@mui/material/Typography';
import { Add, Delete } from '@mui/icons-material';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import IconButton from '@common/button/IconButton';

interface MappingEntry {
  provider: string;
  platform: string;
}

interface OrganizationsMappingValues {
  default_organizations: string[];
  organizations_expr: string[];
  organizations_mapping: MappingEntry[];
}

const AuthProviderOrganizationsFields = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {/* Default organizations */}
      <FieldArray name="organizations_mapping.default_organizations">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
              <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Default organizations')}</Typography>
              <IconButton
                color="primary"
                aria-label={t_i18n('Add')}
                size="default"
                style={{ marginLeft: 8 }}
                onClick={() => push('')}
              >
                <Add fontSize="small" color="primary" />
              </IconButton>
            </div>
            {((form.values as { organizations_mapping: OrganizationsMappingValues }).organizations_mapping.default_organizations ?? []).map((_: string, index: number) => (
              <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`organizations_mapping.default_organizations[${index}]`}
                  label={t_i18n('Organization name')}
                  fullWidth
                />
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Delete')}
                  onClick={() => remove(index)}
                  style={{ marginTop: 10 }}
                >
                  <Delete fontSize="small" />
                </IconButton>
              </div>
            ))}
          </>
        )}
      </FieldArray>

      {/* Organizations expressions */}
      <FieldArray name="organizations_mapping.organizations_expr">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
              <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Organizations expressions')}</Typography>
              <IconButton
                color="primary"
                aria-label={t_i18n('Add')}
                size="default"
                style={{ marginLeft: 8 }}
                onClick={() => push('')}
              >
                <Add fontSize="small" color="primary" />
              </IconButton>
            </div>
            {((form.values as { organizations_mapping: OrganizationsMappingValues }).organizations_mapping.organizations_expr ?? []).map((_: string, index: number) => (
              <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`organizations_mapping.organizations_expr[${index}]`}
                  label={t_i18n('Expression')}
                  fullWidth
                />
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Delete')}
                  onClick={() => remove(index)}
                  style={{ marginTop: 10 }}
                >
                  <Delete fontSize="small" />
                </IconButton>
              </div>
            ))}
          </>
        )}
      </FieldArray>

      {/* Organizations mapping (provider -> platform) */}
      <FieldArray name="organizations_mapping.organizations_mapping">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
              <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Organizations mapping')}</Typography>
              <IconButton
                color="primary"
                aria-label={t_i18n('Add')}
                size="default"
                style={{ marginLeft: 8 }}
                onClick={() => push({ provider: '', platform: '' })}
              >
                <Add fontSize="small" color="primary" />
              </IconButton>
            </div>
            {((form.values as { organizations_mapping: OrganizationsMappingValues }).organizations_mapping.organizations_mapping ?? []).map((_: MappingEntry, index: number) => (
              <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`organizations_mapping.organizations_mapping[${index}].provider`}
                  label={t_i18n('Provider organization')}
                  fullWidth
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name={`organizations_mapping.organizations_mapping[${index}].platform`}
                  label={t_i18n('Platform organization')}
                  fullWidth
                />
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Delete')}
                  onClick={() => remove(index)}
                  style={{ marginTop: 10 }}
                >
                  <Delete fontSize="small" />
                </IconButton>
              </div>
            ))}
          </>
        )}
      </FieldArray>
    </>
  );
};

export default AuthProviderOrganizationsFields;
