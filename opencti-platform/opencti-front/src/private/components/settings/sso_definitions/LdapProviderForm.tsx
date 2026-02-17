import React, { useState } from 'react';
import { Field, FieldArray, Form, Formik } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import { Add, Delete, ExpandMoreOutlined } from '@mui/icons-material';
import SwitchField from '../../../../components/fields/SwitchField';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/fields/SelectField';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { insertNode } from '../../../../utils/store';
import type { Theme } from '../../../../components/Theme';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import AuthProviderGroupsFields from './AuthProviderGroupsFields';
import AuthProviderOrganizationsFields from './AuthProviderOrganizationsFields';
import AuthProviderUserInfoFields from './AuthProviderUserInfoFields';
import AuthProviderLogTab from './AuthProviderLogTab';
import type { LdapProviderFormCreateMutation } from './__generated__/LdapProviderFormCreateMutation.graphql';
import type { LdapProviderFormEditMutation } from './__generated__/LdapProviderFormEditMutation.graphql';
import type { SSODefinitionEditionFragment$data } from './__generated__/SSODefinitionEditionFragment.graphql';
import { PaginationOptions } from '../../../../components/list_lines';

// --- GraphQL Mutations ---

const ldapCreateMutation = graphql`
  mutation LdapProviderFormCreateMutation($input: LdapInput!) {
    ldapProviderAdd(input: $input) {
      ...SSODefinitionsLine_node
    }
  }
`;

const ldapEditMutation = graphql`
  mutation LdapProviderFormEditMutation($id: ID!, $input: LdapInput!) {
    ldapProviderEdit(id: $id, input: $input) {
      ...SSODefinitionsLine_node
    }
  }
`;

// --- Types ---

interface MappingEntry {
  provider: string;
  platform: string;
}

interface ExtraConfEntry {
  type: string;
  key: string;
  value: string;
}

export type LdapProviderData = SSODefinitionEditionFragment$data;

interface LdapFormValues {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override: string;
  url: string;
  bind_dn: string;
  bind_credentials_cleartext: string;
  search_base: string;
  search_filter: string;
  group_base: string;
  group_filter: string;
  allow_self_signed: boolean;
  search_attributes: string;
  username_field: string;
  password_field: string;
  credentials_lookup: string;
  group_search_attributes: string;
  email_expr: string;
  name_expr: string;
  firstname_expr: string;
  lastname_expr: string;
  groups_mapping: {
    default_groups: string[];
    groups_expr: string[];
    group_splitter: string;
    groups_mapping: MappingEntry[];
    auto_create_groups: boolean;
    prevent_default_groups: boolean;
  };
  organizations_mapping: {
    default_organizations: string[];
    organizations_expr: string[];
    organizations_splitter: string;
    organizations_mapping: MappingEntry[];
    auto_create_organizations: boolean;
  };
  extra_conf: ExtraConfEntry[];
}

interface LdapProviderFormProps {
  data?: LdapProviderData;
  onCancel: () => void;
  onCompleted: () => void;
  paginationOptions?: PaginationOptions;
}

// --- Helpers ---

const defaultValues: LdapFormValues = {
  name: '',
  description: '',
  enabled: true,
  button_label_override: '',
  url: '',
  bind_dn: '',
  bind_credentials_cleartext: '',
  search_base: '',
  search_filter: '',
  group_base: '',
  group_filter: '',
  allow_self_signed: false,
  search_attributes: '',
  username_field: '',
  password_field: '',
  credentials_lookup: '',
  group_search_attributes: '',
  email_expr: 'mail',
  name_expr: 'givenName',
  firstname_expr: '',
  lastname_expr: '',
  groups_mapping: {
    default_groups: [],
    groups_expr: ['cn'],
    group_splitter: '',
    groups_mapping: [],
    auto_create_groups: false,
    prevent_default_groups: false,
  },
  organizations_mapping: {
    default_organizations: [],
    organizations_expr: ['organizations'],
    organizations_splitter: '',
    organizations_mapping: [],
    auto_create_organizations: false,
  },
  extra_conf: [],
};

const buildInitialValues = (data: LdapProviderData): LdapFormValues => {
  const conf = data.configuration;
  return {
    name: data.name,
    description: data.description ?? '',
    enabled: data.enabled,
    button_label_override: data.button_label_override ?? '',
    url: conf.url ?? '',
    bind_dn: conf.bind_dn ?? '',
    bind_credentials_cleartext: '',
    search_base: conf.search_base ?? '',
    search_filter: conf.search_filter ?? '',
    group_base: conf.group_base ?? '',
    group_filter: conf.group_filter ?? '',
    allow_self_signed: conf.allow_self_signed ?? false,
    search_attributes: (conf.search_attributes ?? []).join(', '),
    username_field: conf.username_field ?? '',
    password_field: conf.password_field ?? '',
    credentials_lookup: conf.credentials_lookup ?? '',
    group_search_attributes: (conf.group_search_attributes ?? []).join(', '),
    email_expr: conf.user_info_mapping?.email_expr ?? '',
    name_expr: conf.user_info_mapping?.name_expr ?? '',
    firstname_expr: conf.user_info_mapping?.firstname_expr ?? '',
    lastname_expr: conf.user_info_mapping?.lastname_expr ?? '',
    groups_mapping: {
      default_groups: [...(conf.groups_mapping?.default_groups ?? [])],
      groups_expr: [...(conf.groups_mapping?.groups_expr ?? [])],
      group_splitter: conf.groups_mapping?.group_splitter ?? '',
      groups_mapping: (conf.groups_mapping?.groups_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
      auto_create_groups: conf.groups_mapping?.auto_create_groups ?? false,
      prevent_default_groups: conf.groups_mapping?.prevent_default_groups ?? false,
    },
    organizations_mapping: {
      default_organizations: [...(conf.organizations_mapping?.default_organizations ?? [])],
      organizations_expr: [...(conf.organizations_mapping?.organizations_expr ?? [])],
      organizations_splitter: conf.organizations_mapping?.organizations_splitter ?? '',
      organizations_mapping: (conf.organizations_mapping?.organizations_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
      auto_create_organizations: conf.organizations_mapping?.auto_create_organizations ?? false,
    },
    extra_conf: (conf.extra_conf ?? []).map((e) => ({ type: e.type, key: e.key, value: e.value })),
  };
};

// --- Component ---

const LdapProviderForm = ({
  data,
  onCancel,
  onCompleted,
  paginationOptions,
}: LdapProviderFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);
  const isEditing = !!data;

  const [commitCreate] = useApiMutation<LdapProviderFormCreateMutation>(ldapCreateMutation);
  const [commitEdit] = useApiMutation<LdapProviderFormEditMutation>(ldapEditMutation);

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    url: Yup.string().required(t_i18n('This field is required')),
    bind_dn: Yup.string().required(t_i18n('This field is required')),
    search_base: Yup.string().required(t_i18n('This field is required')),
    search_filter: Yup.string().required(t_i18n('This field is required')),
    group_base: Yup.string().required(t_i18n('This field is required')),
    group_filter: Yup.string().required(t_i18n('This field is required')),
    email_expr: Yup.string().required(t_i18n('This field is required')),
    name_expr: Yup.string().required(t_i18n('This field is required')),
    ...(!isEditing && {
      bind_credentials_cleartext: Yup.string().required(t_i18n('This field is required')),
    }),
  });

  const initialValues = data ? buildInitialValues(data) : defaultValues;

  const handleSubmit = (
    values: LdapFormValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    const input = {
      base: {
        name: values.name,
        description: values.description || null,
        enabled: values.enabled,
        button_label_override: values.button_label_override || null,
      },
      configuration: {
        url: values.url,
        bind_dn: values.bind_dn,
        bind_credentials_cleartext: values.bind_credentials_cleartext || null,
        search_base: values.search_base,
        search_filter: values.search_filter,
        group_base: values.group_base,
        group_filter: values.group_filter,
        allow_self_signed: values.allow_self_signed,
        search_attributes: values.search_attributes ? values.search_attributes.split(',').map((s) => s.trim()).filter(Boolean) : null,
        username_field: values.username_field || null,
        password_field: values.password_field || null,
        credentials_lookup: values.credentials_lookup || null,
        group_search_attributes: values.group_search_attributes ? values.group_search_attributes.split(',').map((s) => s.trim()).filter(Boolean) : null,
        user_info_mapping: {
          email_expr: values.email_expr,
          name_expr: values.name_expr,
          firstname_expr: values.firstname_expr || null,
          lastname_expr: values.lastname_expr || null,
        },
        groups_mapping: {
          default_groups: values.groups_mapping.default_groups,
          groups_expr: values.groups_mapping.groups_expr,
          group_splitter: values.groups_mapping.group_splitter || null,
          groups_mapping: values.groups_mapping.groups_mapping,
          auto_create_groups: values.groups_mapping.auto_create_groups,
          prevent_default_groups: values.groups_mapping.prevent_default_groups,
        },
        organizations_mapping: {
          default_organizations: values.organizations_mapping.default_organizations,
          organizations_expr: values.organizations_mapping.organizations_expr,
          organizations_splitter: values.organizations_mapping.organizations_splitter || null,
          organizations_mapping: values.organizations_mapping.organizations_mapping,
          auto_create_organizations: values.organizations_mapping.auto_create_organizations,
        },
        extra_conf: values.extra_conf.map((e) => ({
          type: e.type as 'String' | 'Number' | 'Boolean',
          key: e.key,
          value: e.value,
        })),
      },
    };

    if (isEditing && data) {
      commitEdit({
        variables: { id: data.id, input },
        onCompleted: () => {
          setSubmitting(false);
          onCompleted();
        },
        onError: () => {
          setSubmitting(false);
        },
      });
    } else {
      commitCreate({
        variables: { input },
        updater: (store: RecordSourceSelectorProxy) => {
          if (paginationOptions) {
            insertNode(store, 'Pagination_authenticationProviders', paginationOptions, 'ldapProviderAdd');
          }
        },
        onCompleted: () => {
          setSubmitting(false);
          resetForm();
          onCompleted();
        },
        onError: () => {
          setSubmitting(false);
        },
      });
    }
  };

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={handleSubmit}
      onReset={onCancel}
      enableReinitialize
    >
      {({ handleReset, submitForm, isSubmitting, values }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(_, v) => setCurrentTab(v)}>
              <Tab label={t_i18n('Configuration')} />
              <Tab label={t_i18n('Groups')} />
              <Tab label={t_i18n('Organizations')} />
              <Tab label={t_i18n('Log')} />
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <>
              {/* Enabled at the very top */}
              <Field
                component={SwitchField}
                type="checkbox"
                name="enabled"
                label={t_i18n('Enable LDAP authentication')}
                containerstyle={{ marginTop: 20 }}
              />

              {/* Mandatory fields */}
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Configuration name')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="description"
                label={t_i18n('Description')}
                fullWidth
                multiline
                rows={3}
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="url"
                label={t_i18n('LDAP URL')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="bind_dn"
                label={t_i18n('Bind DN')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="bind_credentials_cleartext"
                label={isEditing ? t_i18n('Bind credentials (leave empty to keep current)') : t_i18n('Bind credentials')}
                fullWidth
                required={!isEditing}
                style={{ marginTop: 20 }}
                type="password"
              />
              <Field
                component={TextField}
                variant="standard"
                name="search_base"
                label={t_i18n('Search base')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="search_filter"
                label={t_i18n('Search filter')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="group_base"
                label={t_i18n('Group base')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="group_filter"
                label={t_i18n('Group filter')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />

              <AuthProviderUserInfoFields />
              <Field
                component={TextField}
                variant="standard"
                name="button_label_override"
                label={t_i18n('Login button label')}
                fullWidth
                style={{ marginTop: 20 }}
              />

              {/* --- Search & Authentication --- */}
              <Accordion variant="outlined" style={{ marginTop: 30 }}>
                <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                  <Typography>{t_i18n('Search & Authentication')}</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ display: 'block' }}>
                  <Field
                    component={SwitchField}
                    type="checkbox"
                    name="allow_self_signed"
                    label={t_i18n('Allow self-signed certificates')}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="search_attributes"
                    label={t_i18n('Search attributes (comma-separated)')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="username_field"
                    label={t_i18n('Username field')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="password_field"
                    label={t_i18n('Password field')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="credentials_lookup"
                    label={t_i18n('Credentials lookup')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="group_search_attributes"
                    label={t_i18n('Group search attributes (comma-separated)')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                </AccordionDetails>
              </Accordion>

              {/* --- Extra configuration --- */}
              <Accordion variant="outlined" style={{ marginTop: 10 }}>
                <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                  <Typography>{t_i18n('Extra configuration')}</Typography>
                </AccordionSummary>
                <AccordionDetails sx={{ display: 'block' }}>
                  <FieldArray name="extra_conf">
                    {({ push, remove }) => (
                      <>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <Typography variant="body2" color="textSecondary" style={{ width: '20%' }}>{t_i18n('Type')}</Typography>
                          <Typography variant="body2" color="textSecondary" style={{ flex: 1 }}>{t_i18n('Key')}</Typography>
                          <Typography variant="body2" color="textSecondary" style={{ flex: 1 }}>{t_i18n('Value')}</Typography>
                          <IconButton
                            color="primary"
                            aria-label={t_i18n('Add')}
                            size="default"
                            onClick={() => push({ type: 'String', key: '', value: '' })}
                          >
                            <Add fontSize="small" color="primary" />
                          </IconButton>
                        </div>
                        {values.extra_conf.length === 0 && (
                          <Typography variant="body2" color="textSecondary" sx={{ fontStyle: 'italic', mt: 1 }}>
                            {t_i18n('No extra configuration entries. Click + to add one.')}
                          </Typography>
                        )}
                        {values.extra_conf.map((_: ExtraConfEntry, index: number) => (
                          <div
                            key={index}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 8,
                              marginTop: 10,
                            }}
                          >
                            <Field
                              component={SelectField}
                              variant="standard"
                              name={`extra_conf[${index}].type`}
                              label={t_i18n('Type')}
                              containerstyle={{ width: '20%' }}
                            >
                              <MenuItem value="String">String</MenuItem>
                              <MenuItem value="Number">Number</MenuItem>
                              <MenuItem value="Boolean">Boolean</MenuItem>
                            </Field>
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`extra_conf[${index}].key`}
                              label={t_i18n('Key')}
                              fullWidth
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`extra_conf[${index}].value`}
                              label={t_i18n('Value')}
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
                </AccordionDetails>
              </Accordion>
            </>
          )}
          {currentTab === 1 && <AuthProviderGroupsFields />}
          {currentTab === 2 && <AuthProviderOrganizationsFields />}
          {currentTab === 3 && <AuthProviderLogTab authLogHistory={data?.authLogHistory ?? []} />}
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
              {t_i18n(isEditing ? 'Update' : 'Create')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default LdapProviderForm;
