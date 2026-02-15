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

interface GroupsMappingValues {
  default_groups: string[];
  groups_expr: string[];
  groups_mapping: MappingEntry[];
}

const AuthProviderGroupsFields = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {/* Default groups */}
      <FieldArray name="groups_mapping.default_groups">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
              <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Default groups')}</Typography>
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
            {((form.values as { groups_mapping: GroupsMappingValues }).groups_mapping.default_groups ?? []).map((_: string, index: number) => (
              <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`groups_mapping.default_groups[${index}]`}
                  label={t_i18n('Group name')}
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

      {/* Groups expressions */}
      <FieldArray name="groups_mapping.groups_expr">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
              <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Groups expressions')}</Typography>
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
            {((form.values as { groups_mapping: GroupsMappingValues }).groups_mapping.groups_expr ?? []).map((_: string, index: number) => (
              <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`groups_mapping.groups_expr[${index}]`}
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

      {/* Groups mapping (provider -> platform) */}
      <FieldArray name="groups_mapping.groups_mapping">
        {({ push, remove, form }) => (
          <>
            <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
              <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Groups mapping')}</Typography>
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
            {((form.values as { groups_mapping: GroupsMappingValues }).groups_mapping.groups_mapping ?? []).map((_: MappingEntry, index: number) => (
              <div key={index} style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name={`groups_mapping.groups_mapping[${index}].provider`}
                  label={t_i18n('Provider group')}
                  fullWidth
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name={`groups_mapping.groups_mapping[${index}].platform`}
                  label={t_i18n('Platform group')}
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

export default AuthProviderGroupsFields;
