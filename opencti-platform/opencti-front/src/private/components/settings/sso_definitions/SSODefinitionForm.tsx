import { useFormatter } from '../../../../components/i18n';
import * as Yup from 'yup';
import { Field, FieldArray, Form, Formik } from 'formik';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import SwitchField from '../../../../components/fields/SwitchField';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { SSODefinitionEditionFragment$data } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import TextField from '../../../../components/TextField';
import { getBaseAndAdvancedConfigFromData } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';
import SAMLConfig from '@components/settings/sso_definitions/SAMLConfig';
import OpenIDConfig from '@components/settings/sso_definitions/OpenIDConfig';
import LDAPConfig from '@components/settings/sso_definitions/LDAPConfig';
import { ConfigurationTypeInput, SingleSignOnAddInput } from '@components/settings/sso_definitions/__generated__/SSODefinitionCreationMutation.graphql';
import Button from '@common/button/Button';
import SSODefinitionGroupForm from '@components/settings/sso_definitions/SSODefinitionGroupForm';
import SSODefinitionOrganizationForm from '@components/settings/sso_definitions/SSODefinitionOrganizationForm';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Add, Delete } from '@mui/icons-material';
import SelectField from 'src/components/fields/SelectField';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { type ConfigurationType, formatAdvancedConfigurationForCreation, formatStringToArray } from './utils/format';
import useFormikToSSOConfig from '@components/settings/sso_definitions/utils/useFormikToSSOConfig';
import { getStrategyConfigEnum } from '@components/settings/sso_definitions/utils/useStrategicConfig';
import { getGroupOrOrganizationMapping } from '@components/settings/sso_definitions/utils/GroupOrOrganizationMapping';
import { SingleSignOnEditInput } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import HeaderConfig from '@components/settings/sso_definitions/HeaderConfig';

interface SSODefinitionFormProps {
  onCancel: () => void;
  onSubmit: (
    values: SingleSignOnAddInput | SingleSignOnEditInput,
    formikHelpers: { setSubmitting: (b: boolean) => void; resetForm: () => void },
  ) => void;
  selectedStrategy: string;
  data?: SSODefinitionEditionFragment$data;
  isOpen?: boolean;
  isEditing?: boolean;
}

export interface SSODefinitionFormValues {
  name: string;
  identifier: string;
  label: string;
  enabled: boolean;
  // SAML - OPENID - LDAP
  advancedConfigurations: ConfigurationType[];
  // SAML
  privateKey: string;
  issuer: string;
  idpCert: string;
  callbackUrl: string;
  wantAssertionsSigned: boolean;
  wantAuthnResponseSigned: boolean;
  loginIdpDirectly: boolean;
  logoutRemote: boolean;
  providerMethod: string;
  signingCert: string;
  ssoBindingType: string;
  forceReauthentication: boolean;
  enableDebugMode: boolean;
  entryPoint: string;
  // Groups
  groups_path: string;
  groups_scope: string;
  group_attribute: string;
  group_attributes: string;
  groups_attributes: string;
  groups_mapping: string[];
  groups_mapping_source: string[];
  groups_mapping_target: string[];
  groups_token_reference: string;
  groups_read_userinfo: boolean;
  // Organizations
  organizations_path: string;
  organizations_scope: string;
  organizations_mapping: string[];
  organizations_mapping_source: string[];
  organizations_mapping_target: string[];
  organizations_token_reference: string;
  organizations_read_userinfo: boolean;
  // OpenID
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  // LDAP
  url: string;
  bindDN: string;
  bindCredentials: string;
  searchBase: string;
  searchFilter: string;
  groupSearchBase: string;
  groupSearchFilter: string;
  allow_self_signed: boolean;
  // Header
  email: string;
  firstname: string;
  lastname: string;
  logout_uri: string;
}

export type SSOEditionFormInputKeys = keyof SSODefinitionFormValues;

type GetSourceAndTargetFromMappingType = {
  source: string[];
  target: string[];
  mapping: string[];
};

const validationSchemaConfiguration = (selectedStrategy: string, t_i18n: (s: string) => string) => {
  const base = {
    name: Yup.string().required(t_i18n('This field is required')),
    identifier: Yup.string().required(t_i18n('This field is required')),
  };

  switch (selectedStrategy) {
    case 'SAML': {
      return Yup.object().shape({
        ...base,
        idpCert: Yup.string().required(t_i18n('This field is required')),
        callbackUrl: Yup.string().required(t_i18n('This field is required')),
        entryPoint: Yup.string().required(t_i18n('This field is required')),
      });
    }
    case 'OpenID': {
      return Yup.object().shape({
        ...base,
        issuer: Yup.string().required(t_i18n('This field is required')),
        client_id: Yup.string().required(t_i18n('This field is required')),
        client_secret: Yup.string().required(t_i18n('This field is required')),
        redirect_uri: Yup.string().required(t_i18n('This field is required')),
      });
    }
    case 'LDAP': {
      return Yup.object().shape({
        ...base,
        url: Yup.string().required(t_i18n('This field is required')),
        bindDN: Yup.string().required(t_i18n('This field is required')),
        searchBase: Yup.string().required(t_i18n('This field is required')),
        searchFilter: Yup.string().required(t_i18n('This field is required')),
        groupSearchBase: Yup.string().required(t_i18n('This field is required')),
        groupSearchFilter: Yup.string().required(t_i18n('This field is required')),
        allow_self_signed: Yup.boolean().required(t_i18n('This field is required')),
      });
    }
    case 'Header': {
      return Yup.object().shape({
        ...base,
        email: Yup.string().required(t_i18n('This field is required')),
        firstname: Yup.string().required(t_i18n('This field is required')),
        lastname: Yup.string().required(t_i18n('This field is required')),
        logout_uri: Yup.string().required(t_i18n('This field is required')),
      });
    }
    default:
      return undefined;
  }
};

const SSODefinitionForm = ({
  data,
  onCancel,
  onSubmit,
  selectedStrategy,
  isEditing,
}: SSODefinitionFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const formikToSSOConfig = useFormikToSSOConfig(selectedStrategy ?? '');

  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };

  const validationSchema = validationSchemaConfiguration(selectedStrategy ?? '', t_i18n);
  const selectedCert = selectedStrategy === 'ClientCert';

  const initialValues: SSODefinitionFormValues = {
    name: '',
    identifier: selectedCert ? 'cert' : '',
    label: '',
    enabled: true,
    // SAML - OPENID - LDAP
    advancedConfigurations: [],
    // SAML
    privateKey: '',
    issuer: '',
    idpCert: '',
    callbackUrl: '',
    wantAssertionsSigned: false,
    wantAuthnResponseSigned: false,
    loginIdpDirectly: false,
    logoutRemote: false,
    providerMethod: '',
    signingCert: '',
    ssoBindingType: '',
    forceReauthentication: false,
    enableDebugMode: false,
    entryPoint: '',
    // Groups
    groups_path: 'groups',
    groups_scope: '',
    group_attribute: '',
    group_attributes: '',
    groups_attributes: '',
    groups_mapping: [],
    groups_mapping_source: [],
    groups_mapping_target: [],
    groups_token_reference: 'access_token',
    groups_read_userinfo: false,
    // Organizations
    organizations_path: '["organizations"]',
    organizations_scope: '',
    organizations_mapping: [],
    organizations_mapping_source: [],
    organizations_mapping_target: [],
    organizations_token_reference: 'access_token',
    organizations_read_userinfo: false,
    // OpenID
    client_id: '',
    client_secret: '',
    redirect_uri: '',
    // LDAP
    url: '',
    bindDN: '',
    bindCredentials: '',
    searchBase: '',
    searchFilter: '',
    groupSearchBase: '',
    groupSearchFilter: '',
    allow_self_signed: false,
    // HEADER
    email: '',
    firstname: '',
    lastname: '',
    logout_uri: '',
  };

  const getSourceAndTargetFromMapping = (groupMapping: string[]) => {
    return groupMapping.reduce((acc: GetSourceAndTargetFromMappingType, cur: string) => {
      const splittedValue = cur.split(':');
      return {
        ...acc,
        source: [...acc.source, splittedValue[0]],
        target: [...acc.target, splittedValue[1]],
      };
    }, { source: [], target: [], mapping: groupMapping });
  };

  const handleSubmit = (
    values: SSODefinitionFormValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    const mainConfigs = formikToSSOConfig(values);

    const advancedConfigs = formatAdvancedConfigurationForCreation(values.advancedConfigurations);

    const configuration = [...mainConfigs, ...advancedConfigs];

    const strategyEnum = getStrategyConfigEnum(selectedStrategy);
    if (!strategyEnum) return;

    const groups_management = {
      group_attribute: values.group_attribute || null,
      group_attributes: formatStringToArray(values.group_attributes) || null,
      groups_attributes: formatStringToArray(values.groups_attributes) || null,
      groups_path: formatStringToArray(values.groups_path) || null,
      groups_scope: values.groups_scope || null,
      groups_mapping: getGroupOrOrganizationMapping(values.groups_mapping_source, values.groups_mapping_target),
      token_reference: values.groups_token_reference,
      read_userinfo: values.groups_read_userinfo,
    };

    const organizations_management = {
      organizations_path: formatStringToArray(values.organizations_path) || null,
      organizations_scope: values.organizations_scope || null,
      organizations_mapping: getGroupOrOrganizationMapping(values.organizations_mapping_source, values.organizations_mapping_target),
      read_userinfo: values.organizations_read_userinfo,
      token_reference: values.organizations_token_reference,
    };

    let finalValues: SingleSignOnAddInput | SingleSignOnEditInput = {
      name: values.name,
      identifier: values.identifier,
      label: values.label,
      enabled: values.enabled,
      strategy: isEditing ? undefined : strategyEnum,
      configuration,
    };

    if (selectedStrategy !== 'ClientCert') {
      finalValues = { ...finalValues, groups_management, organizations_management };
    }

    onSubmit(finalValues, { setSubmitting, resetForm });
  };

  const privateField = data?.configuration?.find((e) => e.key === 'privateKey');
  const issuerField = data?.configuration?.find((e) => e.key === 'issuer');
  const idpCertField = data?.configuration?.find((e) => e.key === 'idpCert');
  const callbackUrlField = data?.configuration?.find((e) => e.key === 'callbackUrl');
  const wantAssertionsSignedField = data?.configuration?.find((e) => e.key === 'wantAssertionsSigned');
  const wantAuthnResponseSignedField = data?.configuration?.find((e) => e.key === 'wantAuthnResponseSigned');
  const loginIdpDirectlyField = data?.configuration?.find((e) => e.key === 'loginIdpDirectly');
  const logoutRemoteField = data?.configuration?.find((e) => e.key === 'logoutRemote');
  const providerMethodField = data?.configuration?.find((e) => e.key === 'providerMethod');
  const signingCertField = data?.configuration?.find((e) => e.key === 'signingCert');
  const ssoBindingTypeField = data?.configuration?.find((e) => e.key === 'ssoBindingType');
  const forceReauthenticationField = data?.configuration?.find((e) => e.key === 'forceReauthentication');
  // const enableDebugModeField = data?.configuration?.find((e) => e.key === 'enableDebugMode');
  const entryPointField = data?.configuration?.find((e) => e.key === 'entryPoint');
  const { advancedConfig: advancedConfigurations } = getBaseAndAdvancedConfigFromData((data?.configuration ?? []) as ConfigurationTypeInput[], selectedStrategy ?? '');

  const groupAttribute = data?.groups_management?.group_attribute;
  const groupAttributes = data?.groups_management?.group_attributes ?? [];
  const groupsAttributes = data?.groups_management?.groups_attributes ?? [];
  const groupsPath = data?.groups_management?.groups_path ?? [];
  const groupsScope = data?.groups_management?.groups_scope ?? '';
  const groupsTokenReference = data?.groups_management?.token_reference;
  const groupsReadUserInfo = data?.groups_management?.read_userinfo;
  const groupsMapping = getSourceAndTargetFromMapping(Array.from(data?.groups_management?.groups_mapping ?? []));

  const organizationsPath = Array.from(data?.organizations_management?.organizations_path ?? []);
  const organizationsScope = data?.organizations_management?.organizations_scope ?? '';
  const organizationsMapping = getSourceAndTargetFromMapping(Array.from(data?.organizations_management?.organizations_mapping ?? []));
  const organizationsTokenReference = data?.organizations_management?.token_reference;
  const organizationsReadUserInfo = data?.organizations_management?.read_userinfo;

  const clientId = data?.configuration?.find((e) => e.key === 'client_id');
  const clientSecret = data?.configuration?.find((e) => e.key === 'client_secret');
  const redirectUri = data?.configuration?.find((e) => e.key === 'redirect_uri');

  const url = data?.configuration?.find((e) => e.key === 'url');
  const bindDN = data?.configuration?.find((e) => e.key === 'bindDN');
  const bindCredentials = data?.configuration?.find((e) => e.key === 'bindCredentials');
  const searchBase = data?.configuration?.find((e) => e.key === 'searchBase');
  const searchFilter = data?.configuration?.find((e) => e.key === 'searchFilter');
  const groupSearchBase = data?.configuration?.find((e) => e.key === 'groupSearchBase');
  const groupSearchFilter = data?.configuration?.find((e) => e.key === 'groupSearchFilter');
  const allow_self_signed = data?.configuration?.find((e) => e.key === 'allow_self_signed');

  const emailField = data?.configuration?.find((e) => e.key === 'email');
  const firstnameField = data?.configuration?.find((e) => e.key === 'firstname');
  const lastnameField = data?.configuration?.find((e) => e.key === 'lastname');
  const logout_uriField = data?.configuration?.find((e) => e.key === 'logout_uri');

  if (data) {
    initialValues.name = data.name;
    initialValues.identifier = data.identifier;
    initialValues.label = data.label || '';
    initialValues.enabled = data.enabled;
    initialValues.privateKey = privateField?.value ?? '';
    initialValues.issuer = issuerField?.value ?? '';
    initialValues.idpCert = idpCertField?.value ?? '';
    initialValues.callbackUrl = callbackUrlField?.value ?? '';
    initialValues.wantAssertionsSigned = wantAssertionsSignedField ? wantAssertionsSignedField?.value === 'true' : true;
    initialValues.wantAuthnResponseSigned = wantAuthnResponseSignedField ? wantAuthnResponseSignedField?.value === 'true' : true;
    initialValues.loginIdpDirectly = loginIdpDirectlyField ? loginIdpDirectlyField?.value === 'true' : false;
    initialValues.logoutRemote = logoutRemoteField ? logoutRemoteField?.value === 'true' : false;
    initialValues.providerMethod = providerMethodField?.value ?? '';
    initialValues.signingCert = signingCertField?.value ?? '';
    initialValues.ssoBindingType = ssoBindingTypeField?.value ?? '';
    initialValues.entryPoint = entryPointField?.value ?? '';
    initialValues.forceReauthentication = forceReauthenticationField ? forceReauthenticationField?.value === 'true' : false;
    // initialValues.enableDebugMode = enableDebugModeField ? enableDebugModeField?.value === 'true' : false;
    initialValues.advancedConfigurations = advancedConfigurations ?? [];

    initialValues.group_attribute = groupAttribute ?? '';
    initialValues.group_attributes = JSON.stringify(groupAttributes);
    initialValues.groups_attributes = JSON.stringify(groupsAttributes);
    initialValues.groups_path = JSON.stringify(groupsPath);
    initialValues.groups_scope = groupsScope;
    initialValues.groups_token_reference = groupsTokenReference ?? '';
    initialValues.groups_read_userinfo = groupsReadUserInfo ?? false;
    initialValues.groups_mapping = groupsMapping.mapping;
    initialValues.groups_mapping_source = groupsMapping.source;
    initialValues.groups_mapping_target = groupsMapping.target;

    initialValues.organizations_path = JSON.stringify(organizationsPath);
    initialValues.organizations_scope = organizationsScope;
    initialValues.organizations_mapping = organizationsMapping.mapping;
    initialValues.organizations_mapping_source = organizationsMapping.source;
    initialValues.organizations_mapping_target = organizationsMapping.target;
    initialValues.organizations_token_reference = organizationsTokenReference ?? '';
    initialValues.organizations_read_userinfo = organizationsReadUserInfo ?? false;

    initialValues.client_id = clientId?.value ?? '';
    initialValues.client_secret = clientSecret?.value ?? '';
    initialValues.redirect_uri = redirectUri?.value ?? '';

    initialValues.url = url?.value ?? '';
    initialValues.bindDN = bindDN?.value ?? '';
    initialValues.bindCredentials = bindCredentials?.value ?? '';
    initialValues.searchBase = searchBase?.value ?? '';
    initialValues.searchFilter = searchFilter?.value ?? '';
    initialValues.groupSearchBase = groupSearchBase?.value ?? '';
    initialValues.groupSearchFilter = groupSearchFilter?.value ?? '';
    initialValues.allow_self_signed = allow_self_signed ? allow_self_signed?.value === 'true' : false;

    initialValues.email = emailField?.value ?? '';
    initialValues.firstname = firstnameField?.value ?? '';
    initialValues.lastname = lastnameField?.value ?? '';
    initialValues.logout_uri = logout_uriField?.value ?? '';
  }

  const showGroupAndMapping = selectedStrategy !== 'LocalAuth' && !selectedCert;

  return (
    <Formik
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={handleSubmit}
      onReset={onCancel}
    >
      {({ handleReset, submitForm, isSubmitting }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={currentTab}
              onChange={(_, value) => handleChangeTab(value)}
            >
              <Tab label={t_i18n('Authentication Configuration')} />
              {showGroupAndMapping && <Tab label={t_i18n('Groups configuration')} />}
              {showGroupAndMapping && <Tab label={t_i18n('Organizations configuration')} />}
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                // onSubmit={updateField}
                label={t_i18n('Configuration Name')}
                fullWidth
                required
                style={{ marginTop: 20 }}
              />
              <div style={{ marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="identifier"
                  label={t_i18n('Authentication Name')}
                  fullWidth
                  required
                  disabled={selectedCert}
                />
              </div>
              <Field
                component={SwitchField}
                variant="standard"
                name="enabled"
                type="checkbox"
                label={t_i18n(`Enable ${selectedStrategy} authentication`)}
                containerstyle={{ marginLeft: 2, marginTop: 20 }}
              />
              {selectedStrategy !== 'LocalAuth' && !selectedCert && (
                <Field
                  component={TextField}
                  variant="standard"
                  name="label"
                  label={t_i18n('Login Button Name')}
                  fullWidth
                  style={{ marginTop: 10 }}
                />
              )}
              {selectedStrategy === 'SAML' && <SAMLConfig />}
              {selectedStrategy === 'OpenID' && <OpenIDConfig />}
              {selectedStrategy === 'LDAP' && <LDAPConfig />}
              {selectedStrategy === 'Header' && <HeaderConfig updateField={updateField} />}
              {!selectedCert && (
                <FieldArray name="advancedConfigurations">
                  {({ push, remove, form }) => (
                    <>
                      <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
                        <Typography variant="h2">{t_i18n('Add more fields')}</Typography>
                        <Tooltip title={t_i18n('For array fields, please add square brackets & each value between double quotes (even for unique value). For example: ["value1", "value2"]')}>
                          <InformationOutline
                            fontSize="small"
                            color="primary"
                            style={{ cursor: 'default', marginLeft: '10px', marginBottom: 12 }}
                          />
                        </Tooltip>
                        <IconButton
                          color="primary"
                          aria-label="Add"
                          size="default"
                          style={{ marginBottom: 12 }}
                          onClick={() => push({ key: '', value: '', type: 'string' })}
                        >
                          <Add fontSize="small" color="primary" />
                        </IconButton>
                      </div>
                      {form.values.advancedConfigurations
                        && form.values.advancedConfigurations.map(
                          (
                            conf: ConfigurationType,
                            index: number,
                          ) => (
                            <div
                              key={index}
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'space-around',
                                marginBottom: 8,
                              }}
                            >
                              <Field
                                component={TextField}
                                variant="standard"
                                name={`advancedConfigurations[${index}].key`}
                                label={t_i18n('Key (in passport)')}
                                containerstyle={{ width: '20%' }}
                              />
                              <Field
                                component={TextField}
                                variant="standard"
                                name={`advancedConfigurations[${index}].value`}
                                label={t_i18n('Value (in IDP)')}
                                containerstyle={{ width: '20%' }}
                              />
                              <Field
                                component={SelectField}
                                variant="standard"
                                name={`advancedConfigurations[${index}].type`}
                                label={t_i18n('Field type')}
                                containerstyle={{ width: '20%' }}
                              >
                                <MenuItem value="string">String</MenuItem>
                                <MenuItem value="number">Number</MenuItem>
                                <MenuItem value="boolean">Boolean</MenuItem>
                                <MenuItem value="array">Array</MenuItem>
                                <MenuItem value="secret">Secret</MenuItem>
                              </Field>
                              <IconButton
                                color="primary"
                                aria-label={t_i18n('Delete')}
                                style={{ marginTop: 10 }}
                                onClick={() => {
                                  remove(index);
                                }}
                              >
                                <Delete fontSize="small" />
                              </IconButton>
                            </div>
                          ),
                        )}
                    </>
                  )}
                </FieldArray>
              )}
            </>
          )}
          {currentTab === 1 && selectedStrategy !== 'LocalAuth' && <SSODefinitionGroupForm selectedStrategy={selectedStrategy} />}
          {currentTab === 2 && selectedStrategy !== 'LocalAuth' && <SSODefinitionOrganizationForm selectedStrategy={selectedStrategy} />}
          <div
            style={{
              marginTop: 20,
              textAlign: 'right',
            }}
          >
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

export default SSODefinitionForm;
