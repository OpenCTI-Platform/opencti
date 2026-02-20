import React from 'react';
import { Field, FieldArray } from 'formik';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import { Add, Delete } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
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
  organizations_splitter: string;
  organizations_mapping: MappingEntry[];
  auto_create_organizations: boolean;
}

const AuthProviderOrganizationsFields = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      <Field
        component={SwitchField}
        type="checkbox"
        name="organizations_mapping.auto_create_organizations"
        label={t_i18n('Auto create organizations')}
        containerstyle={{ marginTop: 20 }}
      />

      {/* Default organizations */}
      <FieldArray name="organizations_mapping.default_organizations">
        {({ push, remove, form }) => {
          const entries = (form.values as { organizations_mapping: OrganizationsMappingValues }).organizations_mapping.default_organizations ?? [];
          return (
            <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
              <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Default organizations')}</Typography>
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Add')}
                  size="default"
                  onClick={() => push('')}
                >
                  <Add fontSize="small" color="primary" />
                </IconButton>
              </Box>
              <Box sx={{ px: 2, pb: entries.length > 0 ? 1 : 0 }}>
                {entries.map((_: string, index: number) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
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
              </Box>
            </Paper>
          );
        }}
      </FieldArray>

      {/* Organizations expressions */}
      <FieldArray name="organizations_mapping.organizations_expr">
        {({ push, remove, form }) => {
          const entries = (form.values as { organizations_mapping: OrganizationsMappingValues }).organizations_mapping.organizations_expr ?? [];
          return (
            <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
              <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Organizations expressions')}</Typography>
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Add')}
                  size="default"
                  onClick={() => push('')}
                >
                  <Add fontSize="small" color="primary" />
                </IconButton>
              </Box>
              <Box sx={{ px: 2, pb: entries.length > 0 ? 1 : 0 }}>
                {entries.map((_: string, index: number) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
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
              </Box>
            </Paper>
          );
        }}
      </FieldArray>

      <Field
        component={TextField}
        variant="standard"
        name="organizations_mapping.organizations_splitter"
        label={t_i18n('Organizations splitter')}
        placeholder=","
        fullWidth
        style={{ marginTop: 20 }}
      />

      {/* Organizations mapping (provider -> platform) */}
      <FieldArray name="organizations_mapping.organizations_mapping">
        {({ push, remove, form }) => {
          const entries = (form.values as { organizations_mapping: OrganizationsMappingValues }).organizations_mapping.organizations_mapping ?? [];
          return (
            <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
              <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Organizations mapping')}</Typography>
                <IconButton
                  color="primary"
                  aria-label={t_i18n('Add')}
                  size="default"
                  onClick={() => push({ provider: '', platform: '' })}
                >
                  <Add fontSize="small" color="primary" />
                </IconButton>
              </Box>
              <Box sx={{ px: 2, pb: entries.length > 0 ? 1 : 0 }}>
                {entries.map((_: MappingEntry, index: number) => (
                  <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
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
              </Box>
            </Paper>
          );
        }}
      </FieldArray>
    </>
  );
};

export default AuthProviderOrganizationsFields;
