import React, { useEffect, useState } from 'react';
import { Field, FieldArray, Form, Formik, useFormikContext } from 'formik';
import * as Yup from 'yup';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Typography from '@mui/material/Typography';
import MenuItem from '@mui/material/MenuItem';
import Paper from '@mui/material/Paper';
import MuiSwitch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
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
import ItemCopy from '../../../../components/ItemCopy';
import useAuth from '../../../../utils/hooks/useAuth';
import AuthProviderGroupsFields from './AuthProviderGroupsFields';
import AuthProviderOrganizationsFields from './AuthProviderOrganizationsFields';
import type { SamlProviderFormCreateMutation } from './__generated__/SamlProviderFormCreateMutation.graphql';
import type { SamlProviderFormEditMutation } from './__generated__/SamlProviderFormEditMutation.graphql';
import type { SSODefinitionEditionFragment$data } from './__generated__/SSODefinitionEditionFragment.graphql';
import { PaginationOptions } from '../../../../components/list_lines';

// --- GraphQL Mutations ---

const samlCreateMutation = graphql`
  mutation SamlProviderFormCreateMutation($input: SamlInput!) {
    samlProviderAdd(input: $input) {
      ...SSODefinitionsLine_node
    }
  }
`;

const samlEditMutation = graphql`
  mutation SamlProviderFormEditMutation($id: ID!, $input: SamlInput!) {
    samlProviderEdit(id: $id, input: $input) {
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

export type SamlProviderData = SSODefinitionEditionFragment$data;

interface SamlFormValues {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override: string;
  identifier_override: string;
  issuer: string;
  entry_point: string;
  idp_certificate: string;
  private_key_cleartext: string;
  logout_remote: boolean;
  want_assertions_signed: boolean;
  want_authn_response_signed: boolean;
  signing_cert: string;
  sso_binding_type: string;
  force_reauthentication: boolean;
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
  extra_conf: ExtraConfEntry[];
}

interface SamlProviderFormProps {
  data?: SamlProviderData;
  onCancel: () => void;
  onCompleted: () => void;
  paginationOptions?: PaginationOptions;
}

// --- Helpers ---

const slugifyIdentifier = (name: string): string => {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

const sanitizeIdentifier = (value: string): string => {
  return value.toLowerCase().replace(/[^a-z0-9-]/g, '');
};

const defaultValues: SamlFormValues = {
  name: '',
  description: '',
  enabled: true,
  button_label_override: '',
  identifier_override: '',
  issuer: '',
  entry_point: '',
  idp_certificate: '',
  private_key_cleartext: '',
  logout_remote: false,
  want_assertions_signed: false,
  want_authn_response_signed: false,
  signing_cert: '',
  sso_binding_type: '',
  force_reauthentication: false,
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
  extra_conf: [],
};

const buildInitialValues = (data: SamlProviderData): SamlFormValues => {
  const conf = data.configuration;
  return {
    name: data.name,
    description: data.description ?? '',
    enabled: data.enabled,
    button_label_override: data.button_label_override ?? '',
    identifier_override: data.identifier_override ?? '',
    issuer: conf.issuer ?? '',
    entry_point: conf.entry_point ?? '',
    idp_certificate: conf.idp_certificate ?? '',
    private_key_cleartext: '',
    logout_remote: conf.logout_remote ?? false,
    want_assertions_signed: conf.want_assertions_signed ?? false,
    want_authn_response_signed: conf.want_authn_response_signed ?? false,
    signing_cert: conf.signing_cert ?? '',
    sso_binding_type: conf.sso_binding_type ?? '',
    force_reauthentication: conf.force_reauthentication ?? false,
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
    extra_conf: (conf.extra_conf ?? []).map((e) => ({ type: e.type, key: e.key, value: e.value })),
  };
};

// --- Sanitize effect for identifier override field ---

const IdentifierSanitizeEffect = () => {
  const { values, setFieldValue } = useFormikContext<SamlFormValues>();
  useEffect(() => {
    if (values.identifier_override) {
      const sanitized = sanitizeIdentifier(values.identifier_override);
      if (sanitized !== values.identifier_override) {
        setFieldValue('identifier_override', sanitized);
      }
    }
  }, [values.identifier_override]);
  return null;
};

// --- Component ---

const SamlProviderForm = ({
  data,
  onCancel,
  onCompleted,
  paginationOptions,
}: SamlProviderFormProps) => {
  const { t_i18n } = useFormatter();
  const { settings } = useAuth();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const isEditing = !!data;
  const [overrideIdentifier, setOverrideIdentifier] = useState(!!data?.identifier_override);

  const [commitCreate] = useApiMutation<SamlProviderFormCreateMutation>(samlCreateMutation);
  const [commitEdit] = useApiMutation<SamlProviderFormEditMutation>(samlEditMutation);

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    issuer: Yup.string().required(t_i18n('This field is required')),
    entry_point: Yup.string().required(t_i18n('This field is required')),
    idp_certificate: Yup.string().required(t_i18n('This field is required')),
    email_expr: Yup.string().required(t_i18n('This field is required')),
    name_expr: Yup.string().required(t_i18n('This field is required')),
    ...(!isEditing && {
      private_key_cleartext: Yup.string().required(t_i18n('This field is required')),
    }),
    ...(overrideIdentifier && {
      identifier_override: Yup.string().trim().required(t_i18n('This field is required')),
    }),
  });

  const initialValues = data ? buildInitialValues(data) : defaultValues;

  const handleSubmit = (
    values: SamlFormValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    const input = {
      base: {
        name: values.name,
        description: values.description || null,
        enabled: values.enabled,
        button_label_override: values.button_label_override || null,
        identifier_override: overrideIdentifier ? (values.identifier_override || null) : null,
      },
      configuration: {
        issuer: values.issuer,
        entry_point: values.entry_point,
        idp_certificate: values.idp_certificate,
        private_key_cleartext: values.private_key_cleartext || null,
        logout_remote: values.logout_remote,
        want_assertions_signed: values.want_assertions_signed,
        want_authn_response_signed: values.want_authn_response_signed,
        signing_cert: values.signing_cert || null,
        sso_binding_type: values.sso_binding_type || null,
        force_reauthentication: values.force_reauthentication,
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
            insertNode(store, 'Pagination_authenticationProviders', paginationOptions, 'samlProviderAdd');
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
      {({ handleReset, submitForm, isSubmitting, values, setFieldValue }) => {
        const effectiveIdentifier = overrideIdentifier && values.identifier_override
          ? values.identifier_override
          : slugifyIdentifier(values.name);
        const computedCallbackUrl = effectiveIdentifier
          ? `${settings.platform_url}/auth/${effectiveIdentifier}/callback`
          : '';

        const handleToggleOverride = (enabled: boolean) => {
          setOverrideIdentifier(enabled);
          if (!enabled) {
            setFieldValue('identifier_override', '');
          }
        };

        return (
          <Form>
            <IdentifierSanitizeEffect />
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
                  label={t_i18n('Enabled')}
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
                  name="issuer"
                  label={t_i18n('Issuer')}
                  fullWidth
                  required
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="entry_point"
                  label={t_i18n('Entry point')}
                  fullWidth
                  required
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="idp_certificate"
                  label={t_i18n('IDP certificate')}
                  fullWidth
                  required
                  multiline
                  rows={4}
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="private_key_cleartext"
                  label={isEditing ? t_i18n('Private key (leave empty to keep current)') : t_i18n('Private key')}
                  fullWidth
                  required={!isEditing}
                  multiline
                  rows={4}
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

                {/* Provider identifier & callback URL */}
                <Paper variant="outlined" sx={{ mt: 3, p: 2, borderRadius: 1 }}>
                  <Typography variant="body2" color="textSecondary">
                    {t_i18n('Callback URL')}
                  </Typography>
                  {computedCallbackUrl ? (
                    <ItemCopy content={computedCallbackUrl} variant="inLine" />
                  ) : (
                    <Typography variant="body2" color="textSecondary" sx={{ fontStyle: 'italic', mt: 0.5 }}>
                      {t_i18n('Enter a configuration name to generate the callback URL.')}
                    </Typography>
                  )}
                  <FormControlLabel
                    control={(
                      <MuiSwitch
                        checked={overrideIdentifier}
                        onChange={(_, checked) => handleToggleOverride(checked)}
                        size="small"
                      />
                    )}
                    label={(
                      <Typography variant="body2">
                        {t_i18n('Customize provider identifier')}
                      </Typography>
                    )}
                    sx={{ mt: 1.5 }}
                  />
                  {overrideIdentifier && (
                    <Field
                      component={TextField}
                      variant="standard"
                      name="identifier_override"
                      label={t_i18n('Provider identifier')}
                      fullWidth
                      required
                      style={{ marginTop: 10 }}
                    />
                  )}
                </Paper>

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
                      name="logout_remote"
                      label={t_i18n('Logout remote')}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="want_assertions_signed"
                      label={t_i18n('Want assertion signed')}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="want_authn_response_signed"
                      label={t_i18n('Want authn response signed')}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="force_reauthentication"
                      label={t_i18n('Force reauthentication')}
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
                      name="signing_cert"
                      label={t_i18n('Signing certificate')}
                      fullWidth
                      multiline
                      rows={4}
                      style={{ marginTop: 20 }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="sso_binding_type"
                      label={t_i18n('SSO Binding type')}
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
                    <FieldArray name="extra_conf">
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
                          {values.extra_conf.map((_: ExtraConfEntry, index: number) => (
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
        );
      }}
    </Formik>
  );
};

export default SamlProviderForm;
