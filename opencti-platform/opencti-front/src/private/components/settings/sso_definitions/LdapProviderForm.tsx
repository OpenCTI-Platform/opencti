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
import type { LdapProviderFormCreateMutation } from './__generated__/LdapProviderFormCreateMutation.graphql';
import type { LdapProviderFormEditMutation } from './__generated__/LdapProviderFormEditMutation.graphql';
import type { SSODefinitionEditionFragment$data } from './__generated__/SSODefinitionEditionFragment.graphql';

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
  email_expr: string;
  name_expr: string;
  firstname_expr: string;
  lastname_expr: string;
  groups_mapping: {
    default_groups: string[];
    groups_expr: string[];
    groups_mapping: MappingEntry[];
  };
  organizations_mapping: {
    default_organizations: string[];
    organizations_expr: string[];
    organizations_mapping: MappingEntry[];
  };
  extra_configuration: ExtraConfEntry[];
}

interface LdapProviderFormProps {
  data?: LdapProviderData;
  onCancel: () => void;
  onCompleted: () => void;
  paginationOptions?: Record<string, unknown>;
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
  email_expr: '',
  name_expr: '',
  firstname_expr: '',
  lastname_expr: '',
  groups_mapping: {
    default_groups: [],
    groups_expr: [],
    groups_mapping: [],
  },
  organizations_mapping: {
    default_organizations: [],
    organizations_expr: [],
    organizations_mapping: [],
  },
  extra_configuration: [],
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
    email_expr: conf.user_info_mapping?.email_expr ?? '',
    name_expr: conf.user_info_mapping?.name_expr ?? '',
    firstname_expr: conf.user_info_mapping?.firstname_expr ?? '',
    lastname_expr: conf.user_info_mapping?.lastname_expr ?? '',
    groups_mapping: {
      default_groups: [...(conf.groups_mapping?.default_groups ?? [])],
      groups_expr: [...(conf.groups_mapping?.groups_expr ?? [])],
      groups_mapping: (conf.groups_mapping?.groups_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
    },
    organizations_mapping: {
      default_organizations: [...(conf.organizations_mapping?.default_organizations ?? [])],
      organizations_expr: [...(conf.organizations_mapping?.organizations_expr ?? [])],
      organizations_mapping: (conf.organizations_mapping?.organizations_mapping ?? []).map((m) => ({ provider: m.provider, platform: m.platform })),
    },
    extra_configuration: (conf.extra_configuration ?? []).map((e) => ({ type: e.type, key: e.key, value: e.value })),
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
  const [advancedOpen, setAdvancedOpen] = useState(false);
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
        user_info_mapping: {
          email_expr: values.email_expr,
          name_expr: values.name_expr,
          firstname_expr: values.firstname_expr || null,
          lastname_expr: values.lastname_expr || null,
        },
        groups_mapping: {
          default_groups: values.groups_mapping.default_groups,
          groups_expr: values.groups_mapping.groups_expr,
          groups_mapping: values.groups_mapping.groups_mapping,
        },
        organizations_mapping: {
          default_organizations: values.organizations_mapping.default_organizations,
          organizations_expr: values.organizations_mapping.organizations_expr,
          organizations_mapping: values.organizations_mapping.organizations_mapping,
        },
        extra_configuration: values.extra_configuration.map((e) => ({
          type: e.type as 'String' | 'Number' | 'Boolean',
          key: e.key,
          string: e.value,
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

              <Typography variant="h4" style={{ marginTop: 30 }}>{t_i18n('User information mapping')}</Typography>
              <Field
                component={TextField}
                variant="standard"
                name="email_expr"
                label={t_i18n('Email expression')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="name_expr"
                label={t_i18n('Name expression')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />

              {/* Advanced configuration - collapsed by default */}
              <Accordion
                expanded={advancedOpen}
                onChange={() => setAdvancedOpen(!advancedOpen)}
                variant="outlined"
                style={{ marginTop: 30 }}
              >
                <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                  <Typography>{t_i18n('Advanced configuration')}</Typography>
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
                    name="description"
                    label={t_i18n('Description')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="button_label_override"
                    label={t_i18n('Login button label')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="firstname_expr"
                    label={t_i18n('First name expression')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name="lastname_expr"
                    label={t_i18n('Last name expression')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />

                  {/* Extra configuration */}
                  <FieldArray name="extra_configuration">
                    {({ push, remove }) => (
                      <>
                        <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
                          <Typography variant="h4" sx={{ m: 0 }}>{t_i18n('Extra configuration')}</Typography>
                          <IconButton
                            color="primary"
                            aria-label={t_i18n('Add')}
                            size="default"
                            style={{ marginLeft: 8 }}
                            onClick={() => push({ type: 'String', key: '', value: '' })}
                          >
                            <Add fontSize="small" color="primary" />
                          </IconButton>
                        </div>
                        {values.extra_configuration.map((_: ExtraConfEntry, index: number) => (
                          <div
                            key={index}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              gap: 8,
                              marginTop: 20,
                            }}
                          >
                            <Field
                              component={SelectField}
                              variant="standard"
                              name={`extra_configuration[${index}].type`}
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
                              name={`extra_configuration[${index}].key`}
                              label={t_i18n('Key')}
                              fullWidth
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`extra_configuration[${index}].value`}
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
