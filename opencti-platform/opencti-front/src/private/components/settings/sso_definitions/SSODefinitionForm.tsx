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
import { getAdvancedConfigFromData } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';
import SAMLConfig from '@components/settings/sso_definitions/SAMLConfig';
import OpenIDConfig from '@components/settings/sso_definitions/OpenIDConfig';
import LDAPConfig from '@components/settings/sso_definitions/LDAPConfig';
import { ConfigurationTypeInput } from '@components/settings/sso_definitions/__generated__/SSODefinitionCreationMutation.graphql';
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

interface SSODefinitionFormProps {
  onCancel: () => void;
  onSubmit?: (
    values: SSODefinitionFormValues,
    formikHelpers: { setSubmitting: (b: boolean) => void; resetForm: () => void },
  ) => void;
  selectedStrategy: string | null;
  onSubmitField?: (field: SSOEditionFormInputKeys, value: unknown) => void;
  data?: SSODefinitionEditionFragment$data;
  isOpen?: boolean;
}

export interface SSODefinitionFormValues {
  name: string;
  identifier: string;
  label: string;
  enabled: boolean;
  // SAML - OPENID - LDAP
  advancedConfigurations: {
    key: string;
    value: string;
    type: string;
  }[];
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
  groups_path: string[];
  groups_scope: string;
  group_attribute: string;
  group_attributes: string[];
  groups_attributes: string[];
  groups_mapping: string[];
  groups_mapping_source: string[];
  groups_mapping_target: string[];
  groups_token_reference: string;
  groups_read_userinfo: boolean;
  // Organizations
  organizations_path: string[];
  organizations_scope: string;
  organizations_mapping: string[];
  organizations_mapping_source: string[];
  organizations_mapping_target: string[];
  organizations_token_reference: string;
  organizations_read_userinfo: boolean;
  // OpenID
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  // LDAP
  url: string;
  bindDN: string;
  bindCredentials: string;
  searchBase: string;
  searchFilter: string;
  groupSearchBase: string;
  groupSearchFilter: string;
  allow_self_signed: boolean;
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
        redirect_uris: Yup.array().of(Yup.string().required(t_i18n('This field is required'))),
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
    default: return undefined;
  }
};

const SSODefinitionForm = ({
  data,
  onCancel,
  onSubmit,
  selectedStrategy,
  onSubmitField,
}: SSODefinitionFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };

  const validationSchema = validationSchemaConfiguration(selectedStrategy ?? '', t_i18n);

  const initialValues: SSODefinitionFormValues = {
    name: '',
    identifier: '',
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
    groups_path: ['groups'],
    groups_scope: '',
    group_attribute: '',
    group_attributes: [],
    groups_attributes: [],
    groups_mapping: [],
    groups_mapping_source: [],
    groups_mapping_target: [],
    groups_token_reference: 'access_token',
    groups_read_userinfo: false,
    // Organizations
    organizations_path: ['organizations'],
    organizations_scope: '',
    organizations_mapping: [],
    organizations_mapping_source: [],
    organizations_mapping_target: [],
    organizations_token_reference: 'access_token',
    organizations_read_userinfo: false,
    // OpenID
    client_id: '',
    client_secret: '',
    redirect_uris: [''],
    // LDAP
    url: '',
    bindDN: '',
    bindCredentials: '',
    searchBase: '',
    searchFilter: '',
    groupSearchBase: '',
    groupSearchFilter: '',
    allow_self_signed: false,
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
  const advancedConfigurations = getAdvancedConfigFromData((data?.configuration ?? []) as ConfigurationTypeInput[], selectedStrategy ?? '');

  const groupAttribute = data?.groups_management?.group_attribute;
  const groupAttributes = Array.from(data?.groups_management?.group_attributes ?? []);
  const groupsAttributes = Array.from(data?.groups_management?.groups_attributes ?? []);
  const groupsPath = Array.from(data?.groups_management?.groups_path ?? []);
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
  const redirectUris = data?.configuration?.find((e) => e.key === 'redirect_uris');

  const url = data?.configuration?.find((e) => e.key === 'url');
  const bindDN = data?.configuration?.find((e) => e.key === 'bindDN');
  const bindCredentials = data?.configuration?.find((e) => e.key === 'bindCredentials');
  const searchBase = data?.configuration?.find((e) => e.key === 'searchBase');
  const searchFilter = data?.configuration?.find((e) => e.key === 'searchFilter');
  const groupSearchBase = data?.configuration?.find((e) => e.key === 'groupSearchBase');
  const groupSearchFilter = data?.configuration?.find((e) => e.key === 'groupSearchFilter');
  const allow_self_signed = data?.configuration?.find((e) => e.key === 'allow_self_signed');

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
    initialValues.group_attributes = groupAttributes;
    initialValues.groups_attributes = groupsAttributes;
    initialValues.groups_path = groupsPath;
    initialValues.groups_scope = groupsScope;
    initialValues.groups_token_reference = groupsTokenReference ?? '';
    initialValues.groups_read_userinfo = groupsReadUserInfo ?? false;
    initialValues.groups_mapping = groupsMapping.mapping;
    initialValues.groups_mapping_source = groupsMapping.source;
    initialValues.groups_mapping_target = groupsMapping.target;

    initialValues.organizations_path = organizationsPath;
    initialValues.organizations_scope = organizationsScope;
    initialValues.organizations_mapping = organizationsMapping.mapping;
    initialValues.organizations_mapping_source = organizationsMapping.source;
    initialValues.organizations_mapping_target = organizationsMapping.target;
    initialValues.organizations_token_reference = organizationsTokenReference ?? '';
    initialValues.organizations_read_userinfo = organizationsReadUserInfo ?? false;

    initialValues.client_id = clientId?.value ?? '';
    initialValues.client_secret = clientSecret?.value ?? '';
    initialValues.redirect_uris = redirectUris?.value ? JSON.parse(redirectUris.value) : [''];

    initialValues.url = url?.value ?? '';
    initialValues.bindDN = bindDN?.value ?? '';
    initialValues.bindCredentials = bindCredentials?.value ?? '';
    initialValues.searchBase = searchBase?.value ?? '';
    initialValues.searchFilter = searchFilter?.value ?? '';
    initialValues.groupSearchBase = groupSearchBase?.value ?? '';
    initialValues.groupSearchFilter = groupSearchFilter?.value ?? '';
    initialValues.allow_self_signed = allow_self_signed ? allow_self_signed?.value === 'true' : false;
  }

  const updateField = async (field: SSOEditionFormInputKeys, value: unknown) => {
    if (onSubmitField) onSubmitField(field, value);
  };

  return (
    <Formik
      enableReinitialize={!updateField}
      initialValues={initialValues}
      validationSchema={validationSchema}
      onSubmit={onSubmit ? onSubmit : () => {}}
      onReset={onCancel}
    >
      {({ handleReset, submitForm, isSubmitting }) => (
        <Form>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={currentTab}
              onChange={(event, value) => handleChangeTab(value)}
            >
              <Tab label={t_i18n('SSO Configuration')} />
              <Tab label={t_i18n('Groups configuration')} />
              <Tab label={t_i18n('Organizations configuration')} />
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                onSubmit={updateField}
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
                  onSubmit={updateField}
                  label={t_i18n('Authentication Name')}
                  fullWidth
                  required
                />
              </div>
              <Field
                component={SwitchField}
                variant="standard"
                name="enabled"
                type="checkbox"
                onChange={updateField}
                label={t_i18n(`Enable ${selectedStrategy} authentication`)}
                containerstyle={{ marginLeft: 2, marginTop: 20 }}
              />
              <Field
                component={TextField}
                variant="standard"
                name="label"
                onSubmit={updateField}
                label={t_i18n('Login Button Name')}
                fullWidth
                style={{ marginTop: 10 }}
              />
              {selectedStrategy === 'SAML' && <SAMLConfig updateField={updateField} />}
              {selectedStrategy === 'OpenID' && <OpenIDConfig updateField={updateField} />}
              {selectedStrategy === 'LDAP' && <LDAPConfig updateField={updateField} />}
              <FieldArray name="advancedConfigurations">
                {({ push, remove, form }) => (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', marginTop: 20 }}>
                      <Typography variant="h2">{t_i18n('Add more fields')}</Typography>
                      <Tooltip title={t_i18n('For array type, to create a list of values, add a comma between each value of your list (ex: value1, value2)')}>
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
                          conf: { key: string; value: string; type: string },
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
                              onSubmit={() => updateField('advancedConfigurations', form.values.advancedConfigurations)}
                              name={`advancedConfigurations[${index}].key`}
                              label={t_i18n('Key (in passport)')}
                              containerstyle={{ width: '20%' }}
                            />
                            <Field
                              component={TextField}
                              variant="standard"
                              onSubmit={() => updateField('advancedConfigurations', form.values.advancedConfigurations)}
                              name={`advancedConfigurations[${index}].value`}
                              label={t_i18n('Value (in IDP)')}
                              containerstyle={{ width: '20%' }}
                            />
                            <Field
                              component={SelectField}
                              variant="standard"
                              onSubmit={() => updateField('advancedConfigurations', form.values.advancedConfigurations)}
                              name={`advancedConfigurations[${index}].type`}
                              label={t_i18n('Field type')}
                              containerstyle={{ width: '20%' }}
                            >
                              <MenuItem value="string">String</MenuItem>
                              <MenuItem value="number">Number</MenuItem>
                              <MenuItem value="boolean">Boolean</MenuItem>
                              <MenuItem value="array">Array</MenuItem>
                            </Field>
                            <IconButton
                              color="primary"
                              aria-label={t_i18n('Delete')}
                              style={{ marginTop: 10 }}
                              onClick={() => {
                                const advancedConfigurations = [...form.values.advancedConfigurations];
                                advancedConfigurations.splice(index, 1);
                                remove(index);
                                updateField('advancedConfigurations', advancedConfigurations);
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
            </>
          )}
          {currentTab === 1 && <SSODefinitionGroupForm updateField={updateField} selectedStrategy={selectedStrategy} isEditionMode={!!onSubmitField} />}
          {currentTab === 2 && <SSODefinitionOrganizationForm updateField={updateField} selectedStrategy={selectedStrategy} isEditionMode={!!onSubmitField} />}
          {!onSubmitField && (
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
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                onClick={submitForm}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Create')}
              </Button>
            </div>
          )}
        </Form>
      )}
    </Formik>
  );
};

export default SSODefinitionForm;
