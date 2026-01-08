import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateSplitControlledDial from '../../../../components/CreateSplitControlledDial';
import SAMLCreation from '@components/settings/sso_definitions/SAMLCreation';
import { Field, Formik, Form, FieldArray } from 'formik';
import { TextField } from 'formik-mui';
import SwitchField from '../../../../components/fields/SwitchField';
import * as Yup from 'yup';
import Tab from '@mui/material/Tab';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Typography from '@mui/material/Typography';
import { IconButton } from '@mui/material';
import { Add, Delete } from '@mui/icons-material';
// import ObjectOrganizationField from '@components/common/form/ObjectOrganizationField';
// import { fieldSpacingContainerStyle } from '../../../../utils/field';
// import GroupField from '@components/common/form/GroupField';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import useFormikToSSOConfig from './useFormikToSSOConfig';

const ssoDefinitionMutation = graphql`
  mutation SSODefinitionCreationMutation(
    $input: SingleSignOnAddInput!
  ) {
    singleSignOnAdd(input: $input) {
      ...SSODefinitionsLine_node
    }
  }
`;

interface SSODefinitionCreationProps {
  paginationOptions: PaginationOptions;
}

export interface SSODefinitionFormValues {
  name: string;
  label: string;
  enabled: boolean;
  private_key: string;
  issuer: string;
  idp_cert: string;
  saml_callback_url: string;
  want_assertions_signed: boolean;
  want_auth_response_signed: boolean;
  login_idp_directly: boolean;
  logout_remote: boolean;
  provider_method: string;
  idp_signing_certificate: string;
  sso_binding_type: string;
  force_reauthentication: boolean;
  enable_debug_mode: boolean;
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
const SSODefinitionCreation: FunctionComponent<SSODefinitionCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [selectedStrategy, setSelectedStrategy] = useState<string | null>(null);
  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  const { formikToSamlConfig } = useFormikToSSOConfig();
  const initialValues = {
    name: '',
    label: '',
    enabled: true,
    // SAML
    private_key: '',
    issuer: '',
    idp_cert: '',
    saml_callback_url: '',
    want_assertions_signed: false,
    want_auth_response_signed: false,
    login_idp_directly: false,
    logout_remote: false,
    provider_method: '',
    idp_signing_certificate: '',
    sso_binding_type: '',
    force_reauthentication: false,
    enable_debug_mode: false,
    advancedConfigurations: [],
    groups_path: [],
    groups_mapping: [],
    read_userinfo: false,
    organizations_path: [],
    organizations_mapping: [],
  };

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    label: Yup.string().required(t_i18n('This field is required')),
    issuer: Yup.string().required(t_i18n('This field is required')),
    idp_cert: Yup.string().required(t_i18n('This field is required')),
    saml_callback_url: Yup.string()
      .url(t_i18n('Must be a valid URL'))
      .required(t_i18n('This field is required')),
  });

  const CreateSSODefinitionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateSplitControlledDial
      entityType="SSODefinition"
      options={[
        'Create SAML',
        'Create OpenID',
        'Create Header',
        'Create ClientCert',
        'Create Ldap',
        'Create LocalAuth',
      ]}
      onOptionClick={(option) => {
        if (option === 'Create SAML') {
          setSelectedStrategy('SAML');
        } else if (option === 'Create OpenID') {
          setSelectedStrategy('OpenID');
        } else if (option === 'Create Header') {
          setSelectedStrategy('Header');
        } else if (option === 'Create ClientCert') {
          setSelectedStrategy('ClientCert');
        } else if (option === 'Create Ldap') {
          setSelectedStrategy('Ldap');
        } else if (option === 'Create LocalAuth') {
          setSelectedStrategy('LocalAuth');
        } else {
          setSelectedStrategy(null);
        }
      }}
      {...props}
    />
  );

  const onSubmit = (
    values: SSODefinitionFormValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    const configuration = formikToSamlConfig(values);

    values.advancedConfigurations.forEach((conf) => {
      if (conf.key && conf.value && conf.type) {
        configuration.push({
          key: conf.key,
          value: conf.value,
          type: conf.type,
        });
      }
    });
    const strategyConfig = selectedStrategy === 'SAML' ? 'SamlStrategy'
      : selectedStrategy === 'OpenID' ? 'OpenIDConnectStrategy'
        : selectedStrategy === 'Header' ? 'HeaderStrategy'
          : selectedStrategy === 'ClientCert' ? 'ClientCertStrategy'
            : selectedStrategy === 'Ldap' ? 'LdapStrategy'
              : selectedStrategy === 'LocalAuth' ? 'LocalStrategy' : null;

    const groups_management = {
      groups_path: values.groups_path || null,
      groups_mapping: values.groups_mapping.filter((v) => v && v.trim() !== ''),
      read_userinfo: values.read_userinfo,
    };
    const organizations_management = {
      organizations_path: values.organizations_path || null,
      organizations_mapping: values.organizations_mapping.filter(
        (v) => v && v.trim() !== '',
      ),
    };
    const finalValues = {
      name: values.name,
      label: values.label,
      enabled: values.enabled,
      strategy: strategyConfig,
      configuration,
      groups_management,
      organizations_management,
    };

    commitMutation({
      ...defaultCommitMutation,
      mutation: ssoDefinitionMutation,
      variables: { input: finalValues },
      updater: (store: RecordSourceSelectorProxy) => {
        insertNode(
          store,
          'Pagination_singleSignOns',
          paginationOptions,
          'singleSignOnAdd',
        );
      },
      setSubmitting,
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        setSelectedStrategy(null);
      },
    });
  };

  return (
    <Drawer
      title={
        selectedStrategy
          ? t_i18n(`Create ${selectedStrategy} SSO`)
          : t_i18n('Create SSO')
      }
      controlledDial={CreateSSODefinitionControlledDial}
    >
      {({ onClose }) => (
        <Formik
          enableReinitialize
          initialValues={initialValues}
          validationSchema={validationSchema}
          onSubmit={onSubmit}
          onReset={onClose}
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
                <Form>
                  <div style={{ marginTop: 20 }}>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="name"
                      label={t_i18n('Configuration Name *')}
                      fullWidth
                    />
                  </div>
                  <Field
                    component={TextField}
                    variant="standard"
                    name="label"
                    label={t_i18n('Login Button Name *')}
                    fullWidth
                    style={{ marginTop: 20 }}
                  />
                  <Field
                    component={SwitchField}
                    variant="standard"
                    name="enabled"
                    type="checkbox"
                    label={t_i18n('Enable SAML authentication')}
                    containerstyle={{ marginLeft: 2, marginTop: 20 }}
                  />
                  {selectedStrategy === 'SAML' && <SAMLCreation />}
                </Form>
              )}
              {currentTab === 1 && (
                <Form>
                  <div style={{ marginTop: 20 }}>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="path"
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
                </Form>
              )}
              {currentTab === 2 && (
                <Form>
                  <div style={{ marginTop: 20 }}>
                    <Field
                      component={TextField}
                      variant="standard"
                      name="path"
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
                </Form>
              )}
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
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};
export default SSODefinitionCreation;
