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
import SecretFieldControl, { type SecretAction, type SecretInfo } from './SecretFieldControl';
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
  callback_url: string;
  issuer: string;
  entry_point: string;
  idp_certificate: string;
  private_key_action: SecretAction;
  private_key_new_value: string;
  logout_remote: boolean;
  want_assertions_signed: boolean;
  want_authn_response_signed: boolean;
  signing_cert: string;
  sso_binding_type: string;
  force_reauthentication: boolean;
  identifier_format: string;
  signature_algorithm: string;
  digest_algorithm: string;
  authn_context: string; // comma-separated, split to array on submit
  disable_requested_authn_context: boolean;
  disable_request_acs_url: boolean;
  skip_request_compression: boolean;
  decryption_pvk_action: SecretAction;
  decryption_pvk_new_value: string;
  decryption_cert: string;
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
  callback_url: '',
  issuer: '',
  entry_point: '',
  idp_certificate: '',
  private_key_action: 'override',
  private_key_new_value: '',
  logout_remote: false,
  want_assertions_signed: false,
  want_authn_response_signed: false,
  signing_cert: '',
  sso_binding_type: '',
  force_reauthentication: false,
  identifier_format: '',
  signature_algorithm: '',
  digest_algorithm: '',
  authn_context: '',
  disable_requested_authn_context: false,
  disable_request_acs_url: false,
  skip_request_compression: false,
  decryption_pvk_action: 'override',
  decryption_pvk_new_value: '',
  decryption_cert: '',
  email_expr: 'email',
  name_expr: 'name',
  firstname_expr: '',
  lastname_expr: '',
  groups_mapping: {
    default_groups: [],
    groups_expr: ['groups'],
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

const buildInitialValues = (data: SamlProviderData): SamlFormValues => {
  const conf = data.configuration;
  return {
    name: data.name,
    description: data.description ?? '',
    enabled: data.enabled,
    button_label_override: data.button_label_override ?? '',
    identifier_override: data.identifier_override ?? '',
    callback_url: conf.callback_url ?? '',
    issuer: conf.issuer ?? '',
    entry_point: conf.entry_point ?? '',
    idp_certificate: conf.idp_certificate ?? '',
    private_key_action: 'keep',
    private_key_new_value: '',
    logout_remote: conf.logout_remote ?? false,
    want_assertions_signed: conf.want_assertions_signed ?? false,
    want_authn_response_signed: conf.want_authn_response_signed ?? false,
    signing_cert: conf.signing_cert ?? '',
    sso_binding_type: conf.sso_binding_type ?? '',
    force_reauthentication: conf.force_reauthentication ?? false,
    identifier_format: conf.identifier_format ?? '',
    signature_algorithm: conf.signature_algorithm ?? '',
    digest_algorithm: conf.digest_algorithm ?? '',
    authn_context: (conf.authn_context ?? []).join(', '),
    disable_requested_authn_context: conf.disable_requested_authn_context ?? false,
    disable_request_acs_url: conf.disable_request_acs_url ?? false,
    skip_request_compression: conf.skip_request_compression ?? false,
    decryption_pvk_action: 'keep',
    decryption_pvk_new_value: '',
    decryption_cert: conf.decryption_cert ?? '',
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
  const isEditing = !!data;
  const [overrideIdentifier, setOverrideIdentifier] = useState(!!data?.identifier_override);
  const [overrideCallbackUrl, setOverrideCallbackUrl] = useState(!!data?.configuration?.callback_url);

  const [commitCreate] = useApiMutation<SamlProviderFormCreateMutation>(samlCreateMutation);
  const [commitEdit] = useApiMutation<SamlProviderFormEditMutation>(samlEditMutation);

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    issuer: Yup.string().required(t_i18n('This field is required')),
    entry_point: Yup.string().required(t_i18n('This field is required')),
    idp_certificate: Yup.string().required(t_i18n('This field is required')),
    email_expr: Yup.string().required(t_i18n('This field is required')),
    name_expr: Yup.string().required(t_i18n('This field is required')),
    ...(overrideIdentifier && {
      identifier_override: Yup.string().trim(),
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
        ...(values.private_key_action === 'keep'
          ? {}
          : { private_key: { new_value_cleartext: values.private_key_new_value || null } }),
        callback_url: overrideCallbackUrl ? (values.callback_url || null) : null,
        logout_remote: values.logout_remote,
        want_assertions_signed: values.want_assertions_signed,
        want_authn_response_signed: values.want_authn_response_signed,
        signing_cert: values.signing_cert || null,
        sso_binding_type: values.sso_binding_type || null,
        force_reauthentication: values.force_reauthentication,
        identifier_format: values.identifier_format || null,
        signature_algorithm: values.signature_algorithm || null,
        digest_algorithm: values.digest_algorithm || null,
        authn_context: values.authn_context ? values.authn_context.split(',').map((s) => s.trim()).filter(Boolean) : null,
        disable_requested_authn_context: values.disable_requested_authn_context,
        disable_request_acs_url: values.disable_request_acs_url,
        skip_request_compression: values.skip_request_compression,
        ...(values.decryption_pvk_action === 'keep'
          ? {}
          : { decryption_pvk: { new_value_cleartext: values.decryption_pvk_new_value || null } }),
        decryption_cert: values.decryption_cert || null,
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
      {({ handleReset, submitForm, isSubmitting, dirty, values, setFieldValue }) => {
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
              </Tabs>
            </Box>
            {currentTab === 0 && (
              <>
                {/* Enabled at the very top */}
                <Field
                  component={SwitchField}
                  type="checkbox"
                  name="enabled"
                  label={t_i18n('Enable SAML authentication')}
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
                <SecretFieldControl
                  secretInfo={(data?.configuration?.private_key ?? null) as SecretInfo | null}
                  namePrefix="private_key"
                  label={t_i18n('Private key')}
                  isEditing={isEditing}
                  multiline
                  style={{ marginTop: 2.5 }}
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

                {/* --- Security & Signing --- */}
                <Accordion variant="outlined" style={{ marginTop: 30 }}>
                  <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                    <Typography>{t_i18n('Security & Signing')}</Typography>
                  </AccordionSummary>
                  <AccordionDetails sx={{ display: 'block' }}>
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
                      component={SelectField}
                      variant="standard"
                      name="signature_algorithm"
                      label={t_i18n('Signature algorithm')}
                      fullWidth
                      containerstyle={{ marginTop: 20, width: '100%' }}
                    >
                      <MenuItem value="">{t_i18n('None')}</MenuItem>
                      <MenuItem value="sha1">sha1</MenuItem>
                      <MenuItem value="sha256">sha256</MenuItem>
                      <MenuItem value="sha512">sha512</MenuItem>
                    </Field>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="digest_algorithm"
                      label={t_i18n('Digest algorithm')}
                      fullWidth
                      style={{ marginTop: 20 }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="identifier_format"
                      label={t_i18n('Identifier format (NameID)')}
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
                    <SecretFieldControl
                      secretInfo={(data?.configuration?.decryption_pvk ?? null) as SecretInfo | null}
                      namePrefix="decryption_pvk"
                      label={t_i18n('Decryption private key')}
                      isEditing={isEditing}
                      multiline
                      style={{ marginTop: 2.5 }}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="decryption_cert"
                      label={t_i18n('Decryption certificate')}
                      fullWidth
                      multiline
                      rows={4}
                      style={{ marginTop: 20 }}
                    />
                  </AccordionDetails>
                </Accordion>

                {/* --- Request behavior --- */}
                <Accordion variant="outlined" style={{ marginTop: 10 }}>
                  <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
                    <Typography>{t_i18n('Request behavior')}</Typography>
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
                      name="force_reauthentication"
                      label={t_i18n('Force reauthentication')}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="disable_requested_authn_context"
                      label={t_i18n('Disable requested authn context')}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="disable_request_acs_url"
                      label={t_i18n('Disable request ACS URL')}
                    />
                    <Field
                      component={SwitchField}
                      type="checkbox"
                      name="skip_request_compression"
                      label={t_i18n('Skip request compression')}
                    />
                    <Field
                      component={TextField}
                      variant="standard"
                      name="authn_context"
                      label={t_i18n('Authentication context (comma-separated)')}
                      fullWidth
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
                disabled={isSubmitting || !dirty}
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
