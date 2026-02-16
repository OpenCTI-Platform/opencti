import React, { useState } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import { Add, Delete } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import PreventDefaultGroupsRow from './PreventDefaultGroupsRow';
import type { CertStrategyFormQuery } from './__generated__/CertStrategyFormQuery.graphql';
import type { CertStrategyFormMutation } from './__generated__/CertStrategyFormMutation.graphql';

const certStrategyFormQuery = graphql`
  query CertStrategyFormQuery {
    settings {
      id
      cert_auth {
        enabled
        button_label
        groups_mapping
        auto_create_group
        prevent_default_groups
        organizations_default
        organizations_mapping
      }
    }
  }
`;

const certStrategyFormMutation = graphql`
  mutation CertStrategyFormMutation($id: ID!, $input: CertAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateCertAuth(input: $input) {
        id
        cert_auth {
          enabled
          button_label
          groups_mapping
          auto_create_group
          prevent_default_groups
          organizations_default
          organizations_mapping
        }
      }
    }
  }
`;

const validationSchema = Yup.object().shape({
  enabled: Yup.boolean(),
  button_label: Yup.string().nullable(),
  auto_create_group: Yup.boolean(),
  prevent_default_groups: Yup.boolean(),
  groups_mapping: Yup.array().of(
    Yup.object().shape({
      source: Yup.string(),
      target: Yup.string(),
    }),
  ),
  organizations_default: Yup.array().of(Yup.string()),
  organizations_mapping: Yup.array().of(
    Yup.object().shape({
      source: Yup.string(),
      target: Yup.string(),
    }),
  ),
});

interface MappingEntry {
  source: string;
  target: string;
}

interface CertStrategyFormValues {
  enabled: boolean;
  button_label: string;
  auto_create_group: boolean;
  prevent_default_groups: boolean;
  groups_mapping: MappingEntry[];
  organizations_default: string[];
  organizations_mapping: MappingEntry[];
}

const parseMappingEntries = (mapping: ReadonlyArray<string | null | undefined> | null | undefined): MappingEntry[] => {
  if (!mapping) return [];
  return mapping
    .filter((s): s is string => s !== null && s !== undefined)
    .map((s) => {
      const parts = s.split(':');
      return { source: parts[0] || '', target: parts[1] || '' };
    });
};

const formatMappingEntries = (entries: MappingEntry[]): string[] => {
  return entries
    .filter((m) => m.source.trim() !== '' || m.target.trim() !== '')
    .map((m) => `${m.source}:${m.target}`);
};

const filterStringArray = (arr: string[]): string[] => {
  return arr.filter((s) => s.trim() !== '');
};

interface CertStrategyFormProps {
  onCancel: () => void;
}

const CertStrategyForm = ({ onCancel }: CertStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const data = useLazyLoadQuery<CertStrategyFormQuery>(certStrategyFormQuery, {});
  const settings = data.settings;
  const certAuth = settings.cert_auth;

  const [commitMutation] = useApiMutation<CertStrategyFormMutation>(
    certStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const initialValues: CertStrategyFormValues = {
    enabled: certAuth?.enabled ?? false,
    button_label: certAuth?.button_label ?? '',
    auto_create_group: certAuth?.auto_create_group ?? false,
    prevent_default_groups: certAuth?.prevent_default_groups ?? false,
    groups_mapping: parseMappingEntries(certAuth?.groups_mapping),
    organizations_default: (certAuth?.organizations_default ?? []).filter((s): s is string => s !== null && s !== undefined),
    organizations_mapping: parseMappingEntries(certAuth?.organizations_mapping),
  };

  const handleSubmit = (
    values: CertStrategyFormValues,
    { setSubmitting }: { setSubmitting: (flag: boolean) => void },
  ) => {
    setSubmitting(true);
    commitMutation({
      variables: {
        id: settings.id,
        input: {
          enabled: values.enabled,
          button_label: values.button_label || null,
          auto_create_group: values.auto_create_group,
          prevent_default_groups: values.prevent_default_groups,
          groups_mapping: formatMappingEntries(values.groups_mapping),
          organizations_default: filterStringArray(values.organizations_default),
          organizations_mapping: formatMappingEntries(values.organizations_mapping),
        },
      },
      onCompleted: () => {
        setSubmitting(false);
        onCancel();
      },
      onError: () => {
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      enableReinitialize
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={handleSubmit}
      onReset={onCancel}
    >
      {({ handleReset, submitForm, isSubmitting }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(_, value) => setCurrentTab(value)}>
              <Tab label={t_i18n('Configuration')} />
              <Tab label={t_i18n('Groups')} />
              <Tab label={t_i18n('Organizations')} />
            </Tabs>
          </Box>

          {/* Tab 0: Configuration */}
          {currentTab === 0 && (
            <>
              <Field
                component={SwitchField}
                type="checkbox"
                name="enabled"
                label={t_i18n('Enable client certificate authentication')}
                containerstyle={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="button_label"
                label={t_i18n('Button label')}
                fullWidth
                style={{ marginTop: 20 }}
              />
            </>
          )}

          {/* Tab 1: Groups */}
          {currentTab === 1 && (
            <>
              <PreventDefaultGroupsRow fieldName="prevent_default_groups" />
              <Field
                component={SwitchField}
                type="checkbox"
                name="auto_create_group"
                label={t_i18n('Auto create group')}
              />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                {t_i18n('Groups are resolved from the OU (Organizational Unit) field of the client certificate.')}
              </Typography>
              {/* Groups mapping - OU:platformGroup pairs */}
              <FieldArray name="groups_mapping">
                {({ push, remove, form }) => {
                  const entries = (form.values as CertStrategyFormValues).groups_mapping;
                  return (
                    <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
                      <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Groups mapping')}</Typography>
                        <IconButton
                          color="primary"
                          aria-label={t_i18n('Add')}
                          size="default"
                          onClick={() => push({ source: '', target: '' })}
                        >
                          <Add fontSize="small" color="primary" />
                        </IconButton>
                      </Box>
                      <Box sx={{ px: 2, pb: entries.length > 0 ? 1 : 0 }}>
                        {entries.map((_: MappingEntry, index: number) => (
                          <div
                            key={index}
                            style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}
                          >
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`groups_mapping[${index}].source`}
                              label={t_i18n('Certificate OU value')}
                              fullWidth
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`groups_mapping[${index}].target`}
                              label={t_i18n('OpenCTI group name')}
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
          )}

          {/* Tab 2: Organizations */}
          {currentTab === 2 && (
            <>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                {t_i18n('Organizations are resolved from the O (Organization) field of the client certificate.')}
              </Typography>
              {/* Organizations mapping - O:platformOrg pairs */}
              <FieldArray name="organizations_mapping">
                {({ push, remove, form }) => {
                  const entries = (form.values as CertStrategyFormValues).organizations_mapping;
                  return (
                    <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
                      <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Organizations mapping')}</Typography>
                        <IconButton
                          color="primary"
                          aria-label={t_i18n('Add')}
                          size="default"
                          onClick={() => push({ source: '', target: '' })}
                        >
                          <Add fontSize="small" color="primary" />
                        </IconButton>
                      </Box>
                      <Box sx={{ px: 2, pb: entries.length > 0 ? 1 : 0 }}>
                        {entries.map((_: MappingEntry, index: number) => (
                          <div
                            key={index}
                            style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}
                          >
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`organizations_mapping[${index}].source`}
                              label={t_i18n('Certificate O value')}
                              fullWidth
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`organizations_mapping[${index}].target`}
                              label={t_i18n('OpenCTI organization name')}
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
              {/* Organizations default - multi-value list */}
              <FieldArray name="organizations_default">
                {({ push, remove, form }) => {
                  const entries = (form.values as CertStrategyFormValues).organizations_default;
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
                          <div
                            key={index}
                            style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}
                          >
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`organizations_default[${index}]`}
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
            </>
          )}

          {/* Shared Cancel / Update buttons */}
          <div style={{ marginTop: 20, textAlign: 'right' }}>
            <Button
              variant="secondary"
              onClick={handleReset}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Cancel')}
            </Button>
            <Button
              onClick={submitForm}
              disabled={isSubmitting}
              style={{ marginLeft: theme.spacing(1) }}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default CertStrategyForm;
