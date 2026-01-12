import { useFormatter } from '../../../../components/i18n';
import * as Yup from 'yup';
import { Field, FieldArray, Form, Formik } from 'formik';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import SwitchField from '../../../../components/fields/SwitchField';
import SAMLCreation from '@components/settings/sso_definitions/SAMLCreation';
import Typography from '@mui/material/Typography';
import { IconButton } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
import Button from '@mui/material/Button';
import React, { useState } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { SSODefinitionEditionFragment$data } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import TextField from '../../../../components/TextField';

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
  groups_mapping: string[];
  organizations_path: string[];
  organizations_mapping: string[];
  read_userinfo: boolean;
}
export type SSOEditionFormInputKeys = keyof SSODefinitionFormValues;

const SSODefinitionForm = ({
  data,
  onCancel,
  onSubmit,
  selectedStrategy,
  onSubmitField }: SSODefinitionFormProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [currentTab, setCurrentTab] = useState(0);

  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    identifier: Yup.string().required(t_i18n('This field is required')),
    issuer: Yup.string().required(t_i18n('This field is required')),
    idpCert: Yup.string().required(t_i18n('This field is required')),
    callbackUrl: Yup.string().required(t_i18n('This field is required')),
    entryPoint: Yup.string().required(t_i18n('This field is required')),
  });
  const initialValues = {
    name: '',
    identifier: '',
    label: '',
    enabled: true,
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
    advancedConfigurations: [],
    groups_path: [],
    groups_mapping: [],
    read_userinfo: false,
    organizations_path: [],
    organizations_mapping: [],
  };
  const privateField = data?.configuration?.find((e) => e.key === 'privateKey');
  const issuerField = data?.configuration?.find((e) => e.key === 'issuer');
  const idpCertField = data?.configuration?.find((e) => e.key === 'idpCertField');
  const callbackUrlField = data?.configuration?.find((e) => e.key === 'callbackUrl');
  const wantAssertionsSignedField = data?.configuration?.find((e) => e.key === 'wantAssertionsSigned');
  const wantAuthnResponseSignedField = data?.configuration?.find((e) => e.key === 'wantAuthnResponseSigned');
  const loginIdpDirectlyField = data?.configuration?.find((e) => e.key === 'loginIdpDirectly');
  const logoutRemoteField = data?.configuration?.find((e) => e.key === 'logoutRemote');
  const providerMethodField = data?.configuration?.find((e) => e.key === 'providerMethod');
  const signingCertField = data?.configuration?.find((e) => e.key === 'signingCert');
  const ssoBindingTypeField = data?.configuration?.find((e) => e.key === 'ssoBindingType');
  const forceReauthenticationField = data?.configuration?.find((e) => e.key === 'forceReauthentication');
  const enableDebugModeField = data?.configuration?.find((e) => e.key === 'enableDebugMode');
  const entryPointField = data?.configuration?.find((e) => e.key === 'entryPoint');

  if (data) {
    initialValues.name = data.name;
    initialValues.identifier = data.identifier;
    initialValues.label = data.label || '';
    initialValues.enabled = data.enabled;
    initialValues.privateKey = privateField?.value ?? '';
    initialValues.issuer = issuerField?.value ?? '';
    initialValues.idpCert = idpCertField?.value ?? '';
    initialValues.callbackUrl = callbackUrlField?.value ?? '';
    initialValues.wantAssertionsSigned = !!wantAssertionsSignedField?.value;
    initialValues.wantAuthnResponseSigned = !!wantAuthnResponseSignedField?.value;
    initialValues.loginIdpDirectly = !!loginIdpDirectlyField?.value;
    initialValues.logoutRemote = !!logoutRemoteField?.value;
    initialValues.providerMethod = providerMethodField?.value ?? '';
    initialValues.signingCert = signingCertField?.value ?? '';
    initialValues.ssoBindingType = ssoBindingTypeField?.value ?? '';
    initialValues.entryPoint = entryPointField?.value ?? '';
    initialValues.forceReauthentication = !!forceReauthenticationField?.value;
    initialValues.enableDebugMode = !!enableDebugModeField?.value;
  }

  const updateField = async (field: SSOEditionFormInputKeys, value: unknown) => {
    if (onSubmitField) {
      // validationSchema.validateAt(field, { [field]: value })
      //   .then(() => onSubmitField(field, value))
      //   .catch(() => false);
      onSubmitField(field, value);
    }
  };

  return (
    <Formik
      enableReinitialize
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
              <Tab label={t_i18n('Groups mapping')} />
              <Tab label={t_i18n('Organization mapping')} />
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
                component={TextField}
                variant="standard"
                name="label"
                onSubmit={updateField}
                label={t_i18n('Login Button Name')}
                fullWidth
                style={{ marginTop: 20 }}
              />
              <Field
                component={SwitchField}
                variant="standard"
                name="enabled"
                type="checkbox"
                onSubmit={updateField}
                label={t_i18n('Enable SAML authentication')}
                containerstyle={{ marginLeft: 2, marginTop: 20 }}
              />
              {selectedStrategy === 'SAML' && <SAMLCreation updateField={updateField} />}
            </>
          )}
          {currentTab === 1 && (
            <>
              <div style={{ marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="groups_path"
                  label={t_i18n('Attribute/path in token')}
                  containerstyle={{ marginTop: 12 }}
                  fullWidth
                />
              </div>
              <FieldArray name="groups_mapping">
                {({ push, remove, form }) => (
                  <>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        marginTop: 20,
                      }}
                    >
                      <Typography variant="h2">Add a group mapping</Typography>
                      <IconButton
                        color="secondary"
                        aria-label="Add a new value"
                        size="large"
                        style={{ marginBottom: 12 }}
                        onClick={() =>
                          push({ value: '', auto_create: 'Boolean' })
                        }
                      >
                        <Add fontSize="small" />
                      </IconButton>
                    </div>
                    {form.values.groups_mapping
                      && form.values.groups_mapping.map(
                        (value: string, index: number) => (
                          <div
                            key={index}
                            style={{
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'space-between',
                              marginBottom: 8,
                            }}
                          >
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`groups_mapping[${index}]`}
                              label={t_i18n('Group mapping value')}
                              fullWidth
                              style={{ marginTop: 20 }}
                            />
                            {/* <div */}
                            {/*  style={{ */}
                            {/*    flexBasis: '70%', */}
                            {/*    maxWidth: '70%', */}
                            {/*    marginBottom: 20, */}
                            {/*  }} */}
                            {/* > */}
                            {/*  <GroupField */}
                            {/*    name="groups" */}
                            {/*    label="Groups" */}
                            {/*    style={fieldSpacingContainerStyle} */}
                            {/*    showConfidence={true} */}
                            {/*  /> */}
                            {/* </div> */}
                            <IconButton
                              color="primary"
                              aria-label={t_i18n('Delete')}
                              style={{ marginTop: 10 }}
                              onClick={() => remove(index)} // Delete
                            >
                              <Delete fontSize="small" />
                            </IconButton>
                            <Field
                              component={SwitchField}
                              variant="standard"
                              type="checkbox"
                              name="auto_create_group"
                              label={t_i18n('auto-create group')}
                              containerstyle={{ marginTop: 10 }}
                            />
                          </div>
                        ),

                      )}
                  </>
                )}
              </FieldArray>
              <Field
                component={SwitchField}
                variant="standard"
                type="checkbox"
                name="read_userinfo"
                label={t_i18n('Automatically add users to default groups')}
                containerstyle={{ marginLeft: 2, marginTop: 30 }}
              />
            </>
          )}
          {currentTab === 2 && (
            <>
              <div style={{ marginTop: 20 }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="organizations_path"
                  label={t_i18n('Attribute/path in token')}
                  fullWidth
                />
              </div>
              <FieldArray name="organizations_mapping">
                {({ push, remove, form }) => (
                  <>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        marginTop: 20,
                      }}
                    >
                      <Typography variant="h2">Add a new value</Typography>
                      <IconButton
                        color="secondary"
                        aria-label="Add a new value"
                        size="large"
                        style={{ marginBottom: 12 }}
                        onClick={() =>
                          push({ value: '', auto_create: 'Boolean' })
                        }
                      >
                        <Add fontSize="small" />
                      </IconButton>
                    </div>
                    {form.values.organizations_mapping
                      && form.values.organizations_mapping.map(
                        (value: string, index: number) => (
                          <div
                            key={index}
                            style={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              marginBottom: 8,
                            }}
                          >
                            <Field
                              component={TextField}
                              variant="standard"
                              name={`organizations_mapping[${index}]`}
                              label={t_i18n('Value organizations mappings')}
                              fullWidth
                              style={{ marginTop: 20 }}
                            />
                            {/* <div */}
                            {/*  style={{ flexBasis: '70%', maxWidth: '70%' }} */}
                            {/* > */}
                            {/*  <ObjectOrganizationField */}
                            {/*    outlined={false} */}
                            {/*    name="objectOrganization" */}
                            {/*    label="Organizations" */}
                            {/*    containerstyle={{ width: '100%' }} */}
                            {/*    style={fieldSpacingContainerStyle} */}
                            {/*    fullWidth */}
                            {/*  /> */}
                            {/* </div> */}
                            <IconButton
                              color="primary"
                              aria-label={t_i18n('Delete')}
                              style={{ marginTop: 30, marginLeft: 50 }}
                              onClick={() => remove(index)}
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
          {!onSubmitField && (
            <div
              style={{
                marginTop: 20,
                textAlign: 'right',
              }}
            >
              <Button
                variant="contained"
                onClick={handleReset}
                disabled={isSubmitting}
                style={{ marginLeft: theme.spacing(2) }}
              >
                {t_i18n('Cancel')}
              </Button>
              <Button
                variant="contained"
                color="secondary"
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
