import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateSplitControlledDial from '../../../../components/CreateSplitControlledDial';
import SAMLCreation, { SAMLCreationValues } from '@components/settings/sso_definitions/SAMLCreation';
import { Field, Formik, Form } from 'formik';
import { TextField } from 'formik-mui';
import SwitchField from '../../../../components/fields/SwitchField';
import * as Yup from 'yup';

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

interface BaseSSOValues {
  name: string;
  label: string;
  enabled: boolean;
}

const SSODefinitionCreation: FunctionComponent<SSODefinitionCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [selectedStrategy, setSelectedStrategy] = useState<string | null>(null);

  const baseInitialValues: BaseSSOValues = {
    name: '',
    label: '',
    enabled: true,
  };

  const validationSchema = Yup.object().shape({
    name: Yup.string().required(t_i18n('This field is required')),
    label: Yup.string().required(t_i18n('This field is required')),
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
    configurationValues: SAMLCreationValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
    baseValues: BaseSSOValues,
  ) => {
    const configuration = [
      {
        key: 'privateKey',
        value: configurationValues.private_key,
        type: 'String',
      },
      {
        key: 'entityId',
        value: configurationValues.entity_id,
        type: 'String',
      },
      {
        key: 'idpCert',
        value: configurationValues.idp_cert,
        type: 'String',
      },
      {
        key: 'callbackUrl',
        value: configurationValues.saml_callback_url,
        type: 'String',
      },
      {
        key: 'assertionSigned',
        value: configurationValues.want_assertions_signed ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'authResponseSigned',
        value: configurationValues.want_auth_response_signed ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'loginIdpDirectly',
        value: configurationValues.login_idp_directly ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'logoutRemote',
        value: configurationValues.logout_remote ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'providerMethod',
        value: configurationValues.provider_method,
        type: 'String',
      },
      {
        key: 'idpSigningCertificate',
        value: configurationValues.idp_signing_certificate,
        type: 'String',
      },
      {
        key: 'ssoBindingType',
        value: configurationValues.sso_binding_type,
        type: 'String',
      },
      {
        key: 'forceReauthentication',
        value: configurationValues.force_reauthentication ? 'true' : 'false',
        type: 'Boolean',
      },
      {
        key: 'enableDebugMode',
        value: configurationValues.enable_debug_mode ? 'true' : 'false',
        type: 'Boolean',
      },
    ];

    const strategyConfig = selectedStrategy === 'SAML' ? 'SamlStrategy'
      : selectedStrategy === 'OpenID' ? 'OpenIDConnectStrategy'
        : selectedStrategy === 'Header' ? 'HeaderStrategy'
          : selectedStrategy === 'ClientCert' ? 'ClientCertStrategy'
            : selectedStrategy === 'Ldap' ? 'LdapStrategy'
              : selectedStrategy === 'LocalAuth' ? 'LocalStrategy' : null;
    const finalValues = {
      name: baseValues.name,
      label: baseValues.label,
      enabled: baseValues.enabled,
      strategy: strategyConfig,
      configuration,
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
          initialValues={baseInitialValues}
          validationSchema={validationSchema}
          onSubmit={() => {}}
          onReset={onClose}
        >
          {({ values }) => (
            <Form>
              <Field
                component={TextField}
                variant="standard"
                name="name"
                label={t_i18n('Configuration Name')}
                fullWidth
              />
              <Field
                component={TextField}
                variant="standard"
                name="label"
                label={t_i18n('Login Button Name')}
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

              {selectedStrategy === 'SAML' && (
                <SAMLCreation
                  initialValues={{}}
                  onSubmit={(samlValues, helpers) =>
                    onSubmit(samlValues, helpers, values)
                  }
                  onCancel={onClose}
                />
              )}
            </Form>
          )}
        </Formik>
      )}
    </Drawer>
  );
};

export default SSODefinitionCreation;
