import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateSplitControlledDial from '../../../../components/CreateSplitControlledDial';

import useFormikToSSOConfig from './utils/useFormikToSSOConfig';
import SSODefinitionForm, { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';

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

const SSODefinitionCreation: FunctionComponent<SSODefinitionCreationProps> = ({
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [selectedStrategy, setSelectedStrategy] = useState<string | null>(null);

  const { formikToSamlConfig } = useFormikToSSOConfig();

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
      identifier: values.identifier,
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
        <SSODefinitionForm
          onCancel={onClose}
          onSubmit={onSubmit}
          selectedStrategy={selectedStrategy}
        />
      )}
    </Drawer>
  );
};
export default SSODefinitionCreation;
