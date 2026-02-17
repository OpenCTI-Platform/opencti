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
import MuiSwitch from '@mui/material/Switch';
import FormControlLabel from '@mui/material/FormControlLabel';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Tooltip from '@mui/material/Tooltip';
import { Add, Delete, ErrorOutlined, ExpandMoreOutlined } from '@mui/icons-material';
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
import AuthProviderUserInfoFields from './AuthProviderUserInfoFields';
import AuthProviderLogTab from './AuthProviderLogTab';
import type { OidcProviderFormCreateMutation } from './__generated__/OidcProviderFormCreateMutation.graphql';
import type { OidcProviderFormEditMutation } from './__generated__/OidcProviderFormEditMutation.graphql';
import type { SSODefinitionEditionFragment$data } from './__generated__/SSODefinitionEditionFragment.graphql';
import { PaginationOptions } from '../../../../components/list_lines';

// --- GraphQL Mutations ---

const oidcCreateMutation = graphql`
  mutation OidcProviderFormCreateMutation($input: OidcInput!) {
    oidcProviderAdd(input: $input) {
      ...SSODefinitionsLine_node
    }
  }
`;

const oidcEditMutation = graphql`
  mutation OidcProviderFormEditMutation($id: ID!, $input: OidcInput!) {
    oidcProviderEdit(id: $id, input: $input) {
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

export type OidcProviderData = SSODefinitionEditionFragment$data;

interface OidcFormValues {
  name: string;
  description: string;
  enabled: boolean;
  button_label_override: string;
  identifier_override: string;
  callback_url: string;
  issuer: string;
  client_id: string;
  client_secret_cleartext: string;
  scopes: string;
  audience: string;
  logout_remote: boolean;
  logout_callback_url: string;
  use_proxy: boolean;
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

interface OidcProviderFormProps {
  data?: OidcProviderData;
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

const defaultValues: OidcFormValues = {
  name: '',
  description: '',
  enabled: true,
  button_label_override: '',
  identifier_override: '',
  callback_url: '',
  issuer: '',
  client_id: '',
  client_secret_cleartext: '',
  scopes: '',
  audience: '',
  logout_remote: false,
  logout_callback_url: '',
  use_proxy: false,
  email_expr: 'user_info.email',
  name_expr: 'user_info.name',
  firstname_expr: 'user_info.given_name',
  lastname_expr: 'user_info.family_name',
  groups_mapping: {
    default_groups: [],
    groups_expr: ['tokens.access_token.groups'],
    group_splitter: '',
    groups_mapping: [],
    auto_create_groups: false,
    prevent_default_groups: false,
  },
  organizations_mapping: {
    default_organizations: [],
    organizations_expr: ['tokens.access_token.organizations'],
    organizations_splitter: '',
    organizations_mapping: [],
    auto_create_organizations: false,
  },
  extra_conf: [],
};

const buildInitialValues = (data: OidcProviderData): OidcFormValues => {
  const conf = data.configuration;
  return {
    name: data.name,
    description: data.description ?? '',
    enabled: data.enabled,
    button_label_override: data.button_label_override ?? '',
    identifier_override: data.identifier_override ?? '',
    callback_url: conf.callback_url ?? '',
    issuer: conf.issuer ?? '',
    client_id: conf.client_id ?? '',
    client_secret_cleartext: '',
    scopes: (conf.scopes ?? []).join(', '),
    audience: conf.audience ?? '',
    logout_remote: conf.logout_remote ?? false,
    logout_callback_url: conf.logout_callback_url ?? '',
    use_proxy: conf.use_proxy ?? false,
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

// --- Sanitize effect for identifier override field ---

const IdentifierSanitizeEffect = () => {
  const { values, setFieldValue } = useFormikContext<OidcFormValues>();
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

const OidcProviderForm = ({
  data,
  onCancel,
  onCompleted,
  paginationOptions,
}: OidcProviderFormProps) => {
  const { t_i18n } = useFormatter();
  const { settings } = useAuth();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);
  const isEditing = !!data;
  const [overrideIdentifier, setOverrideIdentifier] = useState(!!data?.identifier_override);
  const [overrideCallbackUrl, setOverrideCallbackUrl] = useState(!!data?.configuration?.callback_url);

  const [commitCreate] = useApiMutation<OidcProviderFormCreateMutation>(oidcCreateMutation);
  const [commitEdit] = useApiMutation<OidcProviderFormEditMutation>(oidcEditMutation);

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    issuer: Yup.string().required(t_i18n('This field is required')),
    client_id: Yup.string().required(t_i18n('This field is required')),
    email_expr: Yup.string().required(t_i18n('This field is required')),
    name_expr: Yup.string().required(t_i18n('This field is required')),
    ...(!isEditing && {
      client_secret_cleartext: Yup.string().required(t_i18n('This field is required')),
    }),
    ...(overrideIdentifier && {
      identifier_override: Yup.string().trim(),
    }),
  });

  const initialValues = data ? buildInitialValues(data) : defaultValues;

  const handleSubmit = (
    values: OidcFormValues,
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
        client_id: values.client_id,
        client_secret_cleartext: values.client_secret_cleartext || null,
        callback_url: overrideCallbackUrl ? (values.callback_url || null) : null,
        scopes: values.scopes ? values.scopes.split(',').map((s) => s.trim()).filter(Boolean) : [],
        audience: values.audience || null,
        logout_remote: values.logout_remote,
        logout_callback_url: values.logout_callback_url || null,
        use_proxy: values.use_proxy,
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
            insertNode(store, 'Pagination_authenticationProviders', paginationOptions, 'oidcProviderAdd');
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

        const handleToggleCallbackUrl = (enabled: boolean) => {
          setOverrideCallbackUrl(enabled);
          if (!enabled) {
            setFieldValue('callback_url', '');
          }
        };

        const displayedCallbackUrl = overrideCallbackUrl && values.callback_url
          ? values.callback_url
          : computedCallbackUrl;

        // Detect mismatch between callback URL override and the effective identifier
        const callbackUrlMismatch = overrideCallbackUrl
          && values.callback_url
          && effectiveIdentifier
          && !values.callback_url.includes(`/auth/${effectiveIdentifier}/callback`);

        return (
          <Form>
            <IdentifierSanitizeEffect />
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={currentTab} onChange={(_, v) => setCurrentTab(v)}>
                <Tab label={t_i18n('Configuration')} />
                <Tab label={t_i18n('Groups')} />
                <Tab label={t_i18n('Organizations')} />
                <Tab label={t_i18n('Logs')} />
              </Tabs>
            </Box>
            {currentTab === 0 && (
              <>
                {/* Enabled at the very top */}
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="enabled"
                  label={t_i18n('Enable OIDC authentication')}
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

                {/* Provider routing — right below Configuration name */}
                <Accordion
                  variant="outlined"
                  defaultExpanded={overrideIdentifier || overrideCallbackUrl}
                  sx={{ mt: 2, borderRadius: 1, overflow: 'hidden', '&:before': { display: 'none' } }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreOutlined />} sx={{ px: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, overflow: 'hidden', width: '100%' }}>
                      <Typography variant="caption" color="textSecondary" sx={{ whiteSpace: 'nowrap' }}>
                        {t_i18n('Callback URL')}
                      </Typography>
                      {displayedCallbackUrl ? (
                        <ItemCopy content={displayedCallbackUrl} variant="inLine" />
                      ) : (
                        <Typography variant="body2" color="textSecondary" sx={{ fontStyle: 'italic' }}>
                          {t_i18n('Enter a configuration name to generate the callback URL.')}
                        </Typography>
                      )}
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails sx={{ px: 2, pb: 3 }}>
                    <Box sx={{
                      display: 'grid',
                      gridTemplateColumns: 'auto 1fr',
                      alignItems: 'end',
                      columnGap: 2,
                      rowGap: 2,
                    }}
                    >
                      <FormControlLabel
                        control={(
                          <MuiSwitch
                            checked={overrideIdentifier}
                            onChange={(_, checked) => handleToggleOverride(checked)}
                            size="small"
                          />
                        )}
                        label={t_i18n('Override identifier')}
                        componentsProps={{ typography: { variant: 'body2' } }}
                        sx={{ m: 0 }}
                      />
                      <Field
                        component={TextField}
                        variant="standard"
                        name="identifier_override"
                        label={t_i18n('Provider identifier')}
                        placeholder={slugifyIdentifier(values.name) || undefined}
                        InputLabelProps={{ shrink: true }}
                        fullWidth
                        size="small"
                        disabled={!overrideIdentifier}
                      />
                      <FormControlLabel
                        control={(
                          <MuiSwitch
                            checked={overrideCallbackUrl}
                            onChange={(_, checked) => handleToggleCallbackUrl(checked)}
                            size="small"
                          />
                        )}
                        label={t_i18n('Override callback URL')}
                        componentsProps={{ typography: { variant: 'body2' } }}
                        sx={{ m: 0 }}
                      />
                      {overrideCallbackUrl ? (
                        <Box sx={{ display: 'flex', alignItems: 'flex-end', gap: 1 }}>
                          <Field
                            component={TextField}
                            variant="standard"
                            name="callback_url"
                            label={t_i18n('Callback URL override')}
                            fullWidth
                            size="small"
                          />
                          {callbackUrlMismatch && (
                            <Tooltip
                              title={t_i18n('The callback URL does not contain the expected identifier path. The authentication callback will not work unless the URL includes "/auth/{identifier}/callback" where {identifier} matches the provider identifier.')}
                            >
                              <ErrorOutlined color="error" sx={{ mb: 0.5, fontSize: 20 }} />
                            </Tooltip>
                          )}
                        </Box>
                      ) : <span />}
                    </Box>
                  </AccordionDetails>
                </Accordion>
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
                  name="issuer"
                  label={t_i18n('Issuer')}
                  fullWidth
                  required
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="client_id"
                  label={t_i18n('Client ID')}
                  fullWidth
                  required
                  style={{ marginTop: 20 }}
                />
                <Field
                  component={TextField}
                  variant="standard"
                  name="client_secret_cleartext"
                  label={isEditing ? t_i18n('Client secret (leave empty to keep current)') : t_i18n('Client secret')}
                  fullWidth
                  required={!isEditing}
                  style={{ marginTop: 20 }}
                  type="password"
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

                {/* --- Protocol & Scopes --- */}
                <Accordion variant="outlined" style={{ marginTop: 30 }}>
                  <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                    <Typography>{t_i18n('Protocol & Scopes')}</Typography>
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
                      name="use_proxy"
                      label={t_i18n('Use proxy')}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="scopes"
                      label={t_i18n('Scopes (comma-separated, defaults to openid email profile)')}
                      fullWidth
                      style={{ marginTop: 20 }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="audience"
                      label={t_i18n('Audience')}
                      fullWidth
                      style={{ marginTop: 20 }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="logout_callback_url"
                      label={t_i18n('Logout callback URL')}
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
        );
      }}
    </Formik>
  );
};

export default OidcProviderForm;
