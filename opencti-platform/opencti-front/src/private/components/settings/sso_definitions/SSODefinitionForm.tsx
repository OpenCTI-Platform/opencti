import { useFormatter } from '../../../../components/i18n';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
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
import { ConfigurationTypeInput } from '@components/settings/sso_definitions/__generated__/SSODefinitionCreationMutation.graphql';
import Button from '@common/button/Button';
import SSODefinitionGroupForm from '@components/settings/sso_definitions/SSODefinitionGroupForm';
import SSODefinitionOrganizationForm from '@components/settings/sso_definitions/SSODefinitionOrganizationForm';

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
  advancedConfigurations: {
    key: string;
    value: string;
    type: string;
  }[];
  groups_path: string[];
  group_attributes: string[];
  groups_attributes: string[];
  groups_mapping: string[];
  organizations_path: string[];
  organizations_mapping: string[];
  organizations_mapping_source: string[];
  organizations_mapping_target: { label: string; value: string }[];
  read_userinfo: boolean;
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
}
export type SSOEditionFormInputKeys = keyof SSODefinitionFormValues;

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
    name: 'aze',
    identifier: 'aze',
    label: 'aze',
    enabled: true,
    // SAML
    privateKey: '',
    issuer: 'aze',
    idpCert: 'aze',
    callbackUrl: 'aze',
    wantAssertionsSigned: false,
    wantAuthnResponseSigned: false,
    loginIdpDirectly: false,
    logoutRemote: false,
    providerMethod: '',
    signingCert: '',
    ssoBindingType: '',
    forceReauthentication: false,
    enableDebugMode: false,
    entryPoint: 'aze',
    advancedConfigurations: [],
    groups_path: [],
    group_attributes: [],
    groups_attributes: [],
    groups_mapping: [],
    read_userinfo: false,
    organizations_path: [],
    organizations_mapping: [],
    organizations_mapping_source: [],
    organizations_mapping_target: [],
    // OpenID
    client_id: '',
    client_secret: '',
    redirect_uris: [''],
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

  const groupAttributes = Array.from(data?.groups_management?.group_attributes ?? []);
  const groupsAttributes = Array.from(data?.groups_management?.groups_attributes ?? []);
  const groupsPath = Array.from(data?.groups_management?.groups_path ?? []);
  const groupsMapping = Array.from(data?.groups_management?.groups_mapping ?? []);

  const organizationsPath = Array.from(data?.organizations_management?.organizations_path ?? []);
  const organizationsMapping = Array.from(data?.organizations_management?.organizations_mapping ?? []);

  const clientId = data?.configuration?.find((e) => e.key === 'client_id');
  const clientSecret = data?.configuration?.find((e) => e.key === 'client_secret');
  const redirectUris = data?.configuration?.find((e) => e.key === 'redirect_uris');

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
    initialValues.groups_attributes = groupsAttributes;
    initialValues.group_attributes = groupAttributes;
    initialValues.groups_path = groupsPath;
    initialValues.groups_mapping = groupsMapping;
    initialValues.organizations_path = organizationsPath;
    initialValues.organizations_mapping = organizationsMapping;
    // initialValues.organizations_mapping_source = ??;
    // initialValues.organizations_mapping_target = ??;
    initialValues.client_id = clientId?.value ?? '';
    initialValues.client_secret = clientSecret?.value ?? '';
    initialValues.redirect_uris = redirectUris?.value ? JSON.parse(redirectUris.value) : [''];
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
            </>
          )}
          {currentTab === 1 && <SSODefinitionGroupForm updateField={updateField} selectedStrategy={selectedStrategy} />}
          {currentTab === 2 && <SSODefinitionOrganizationForm updateField={updateField} />}
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
