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
import type { HeaderStrategyFormQuery } from './__generated__/HeaderStrategyFormQuery.graphql';
import type { HeaderStrategyFormMutation } from './__generated__/HeaderStrategyFormMutation.graphql';

const headerStrategyFormQuery = graphql`
  query HeaderStrategyFormQuery {
    settings {
      id
      headers_auth {
        enabled
        header_email
        header_name
        header_firstname
        header_lastname
        logout_uri
        auto_create_group
        prevent_default_groups
        headers_audit
        groups_header
        groups_splitter
        groups_mapping
        organizations_default
        organizations_header
        organizations_splitter
        organizations_mapping
      }
    }
  }
`;

const headerStrategyFormMutation = graphql`
  mutation HeaderStrategyFormMutation($id: ID!, $input: HeadersAuthConfigInput!) {
    settingsEdit(id: $id) {
      updateHeaderAuth(input: $input) {
        id
        headers_auth {
          enabled
          header_email
          header_name
          header_firstname
          header_lastname
          logout_uri
          auto_create_group
          prevent_default_groups
          headers_audit
          groups_header
          groups_splitter
          groups_mapping
          organizations_default
          organizations_header
          organizations_splitter
          organizations_mapping
        }
      }
    }
  }
`;

const validationSchema = Yup.object().shape({
  enabled: Yup.boolean(),
  header_email: Yup.string().required('This field is required'),
  header_name: Yup.string().nullable(),
  header_firstname: Yup.string().nullable(),
  header_lastname: Yup.string().nullable(),
  logout_uri: Yup.string().nullable(),
  headers_audit: Yup.array().of(Yup.string()),
  auto_create_group: Yup.boolean(),
  prevent_default_groups: Yup.boolean(),
  groups_header: Yup.string().nullable(),
  groups_splitter: Yup.string().nullable(),
  groups_mapping: Yup.array().of(
    Yup.object().shape({
      source: Yup.string(),
      target: Yup.string(),
    }),
  ),
  organizations_default: Yup.array().of(Yup.string()),
  organizations_header: Yup.string().nullable(),
  organizations_splitter: Yup.string().nullable(),
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

interface HeaderStrategyFormValues {
  enabled: boolean;
  header_email: string;
  header_name: string;
  header_firstname: string;
  header_lastname: string;
  logout_uri: string;
  headers_audit: string[];
  auto_create_group: boolean;
  prevent_default_groups: boolean;
  groups_header: string;
  groups_splitter: string;
  groups_mapping: MappingEntry[];
  organizations_default: string[];
  organizations_header: string;
  organizations_splitter: string;
  organizations_mapping: MappingEntry[];
}
// ReadonlyArray<string | null | undefined> | null | undefined
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

interface HeaderStrategyFormProps {
  onCancel: () => void;
}

const HeaderStrategyForm = ({ onCancel }: HeaderStrategyFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const data = useLazyLoadQuery<HeaderStrategyFormQuery>(headerStrategyFormQuery, {});
  const settings = data.settings;
  const headerAuth = settings.headers_auth;

  const [commitMutation] = useApiMutation<HeaderStrategyFormMutation>(
    headerStrategyFormMutation,
    undefined,
    { successMessage: t_i18n('Authentication successfully updated') },
  );

  const initialValues: HeaderStrategyFormValues = {
    enabled: headerAuth?.enabled ?? false,
    header_email: headerAuth?.header_email ?? '',
    header_name: headerAuth?.header_name ?? '',
    header_firstname: headerAuth?.header_firstname ?? '',
    header_lastname: headerAuth?.header_lastname ?? '',
    logout_uri: headerAuth?.logout_uri ?? '',
    headers_audit: (headerAuth?.headers_audit ?? []).filter((s): s is string => s !== null && s !== undefined),
    auto_create_group: headerAuth?.auto_create_group ?? false,
    prevent_default_groups: headerAuth?.prevent_default_groups ?? false,
    groups_header: headerAuth?.groups_header ?? '',
    groups_splitter: headerAuth?.groups_splitter ?? '',
    groups_mapping: parseMappingEntries(headerAuth?.groups_mapping),
    organizations_default: (headerAuth?.organizations_default ?? []).filter((s): s is string => s !== null && s !== undefined),
    organizations_header: headerAuth?.organizations_header ?? '',
    organizations_splitter: headerAuth?.organizations_splitter ?? '',
    organizations_mapping: parseMappingEntries(headerAuth?.organizations_mapping),
  };

  const handleSubmit = (
    values: HeaderStrategyFormValues,
    { setSubmitting }: { setSubmitting: (flag: boolean) => void },
  ) => {
    setSubmitting(true);
    commitMutation({
      variables: {
        id: settings.id,
        input: {
          enabled: values.enabled,
          header_email: values.header_email,
          header_name: values.header_name || null,
          header_firstname: values.header_firstname || null,
          header_lastname: values.header_lastname || null,
          logout_uri: values.logout_uri || null,
          headers_audit: filterStringArray(values.headers_audit),
          auto_create_group: values.auto_create_group,
          prevent_default_groups: values.prevent_default_groups,
          groups_header: values.groups_header || null,
          groups_splitter: values.groups_splitter || null,
          groups_mapping: formatMappingEntries(values.groups_mapping),
          organizations_default: filterStringArray(values.organizations_default),
          organizations_header: values.organizations_header || null,
          organizations_splitter: values.organizations_splitter || null,
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

          {/* Tab 1: Configuration */}
          {currentTab === 0 && (
            <>
              <Field
                component={SwitchField}
                type="checkbox"
                name="enabled"
                label={t_i18n('Enable header authentication')}
                containerstyle={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="header_email"
                label={t_i18n('Email header name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="header_name"
                label={t_i18n('Name header name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="header_firstname"
                label={t_i18n('Firstname header name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="header_lastname"
                label={t_i18n('Lastname header name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="logout_uri"
                label={t_i18n('Logout URI')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              {/* Headers audit - multi-value list */}
              <FieldArray name="headers_audit">
                {({ push, remove, form }) => {
                  const entries = (form.values as HeaderStrategyFormValues).headers_audit;
                  return (
                    <Paper variant="outlined" sx={{ mt: 2, borderRadius: 1, overflow: 'hidden' }}>
                      <Box sx={{ px: 2, py: 1, backgroundColor: 'action.hover', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Headers audit')}</Typography>
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
                              name={`headers_audit[${index}]`}
                              label={t_i18n('Header name')}
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

          {/* Tab 2: Groups */}
          {currentTab === 1 && (
            <>
              <PreventDefaultGroupsRow fieldName="prevent_default_groups" />
              <Field
                component={SwitchField}
                type="checkbox"
                name="auto_create_group"
                label={t_i18n('Auto create group')}
              />
              <Field
                component={TextField}
                variant="standard"
                name="groups_header"
                label={t_i18n('Groups header name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="groups_splitter"
                label={t_i18n('Groups splitter')}
                placeholder=","
                fullWidth
                style={{ marginTop: 20 }}
              />
              {/* Groups mapping - source:target pairs */}
              <FieldArray name="groups_mapping">
                {({ push, remove, form }) => {
                  const entries = (form.values as HeaderStrategyFormValues).groups_mapping;
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
                              label={t_i18n('Remote group name')}
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

          {/* Tab 3: Organizations */}
          {currentTab === 2 && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="organizations_header"
                label={t_i18n('Organizations header name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="organizations_splitter"
                label={t_i18n('Organizations splitter')}
                placeholder=","
                fullWidth
                style={{ marginTop: 20 }}
              />
              {/* Organizations mapping - source:target pairs */}
              <FieldArray name="organizations_mapping">
                {({ push, remove, form }) => {
                  const entries = (form.values as HeaderStrategyFormValues).organizations_mapping;
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
                              label={t_i18n('Remote organization name')}
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
                  const entries = (form.values as HeaderStrategyFormValues).organizations_default;
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

export default HeaderStrategyForm;
