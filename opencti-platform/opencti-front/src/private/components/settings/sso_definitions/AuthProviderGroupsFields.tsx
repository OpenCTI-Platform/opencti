import React from 'react';
import { Field, FieldArray } from 'formik';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import { Add, Delete } from '@mui/icons-material';
import TextField from '../../../../components/TextField';
import SwitchField from '../../../../components/fields/SwitchField';
import { useFormatter } from '../../../../components/i18n';
import IconButton from '@common/button/IconButton';
import PreventDefaultGroupsRow from './PreventDefaultGroupsRow';

interface MappingEntry {
  provider: string;
  platform: string;
}

interface GroupsMappingValues {
  default_groups: string[];
  groups_expr: string[];
  group_splitter: string;
  groups_mapping: MappingEntry[];
  auto_create_groups: boolean;
  prevent_default_groups: boolean;
}

const AuthProviderGroupsFields = () => {
  const { t_i18n } = useFormatter();

  return (
    <>
      {/* Prevent default groups - always at the top */}
      <PreventDefaultGroupsRow fieldName="groups_mapping.prevent_default_groups" />
      <Field
        component={SwitchField}
        type="checkbox"
        name="groups_mapping.auto_create_groups"
        label={t_i18n('Auto create groups')}
      />

      {/* Default groups */}
      <FieldArray name="groups_mapping.default_groups">
        {({ push, remove, form }) => {
          const entries = (form.values as { groups_mapping: GroupsMappingValues }).groups_mapping.default_groups ?? [];
          return (
            <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
              <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Default groups')}</Typography>
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
              </Box>
            </Paper>
          );
        }}
      </FieldArray>

      {/* Groups expressions */}
      <FieldArray name="groups_mapping.groups_expr">
        {({ push, remove, form }) => {
          const entries = (form.values as { groups_mapping: GroupsMappingValues }).groups_mapping.groups_expr ?? [];
          return (
            <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
              <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Groups expressions')}</Typography>
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
              </Box>
            </Paper>
          );
        }}
      </FieldArray>

      <Field
        component={TextField}
        variant="standard"
        name="groups_mapping.group_splitter"
        label={t_i18n('Groups splitter')}
        placeholder=","
        fullWidth
        style={{ marginTop: 20 }}
      />

      {/* Groups mapping (provider -> platform) */}
      <FieldArray name="groups_mapping.groups_mapping">
        {({ push, remove, form }) => {
          const entries = (form.values as { groups_mapping: GroupsMappingValues }).groups_mapping.groups_mapping ?? [];
          return (
            <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
              <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Groups mapping')}</Typography>
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
              </Box>
            </Paper>
          );
        }}
      </FieldArray>
    </>
  );
};

export default AuthProviderGroupsFields;
