import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateSplitControlledDial from '../../../../components/CreateSplitControlledDial';
import { getGroupOrOrganizationMapping } from './utils/GroupOrOrganizationMapping';
import useFormikToSSOConfig from './utils/useFormikToSSOConfig';
import SSODefinitionForm, { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionForm';
import { getStrategyConfigEnum } from '@components/settings/sso_definitions/utils/useStrategicConfig';

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

  const formikToSSOConfig = useFormikToSSOConfig(selectedStrategy ?? '');

  const CreateSSODefinitionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateSplitControlledDial
      entityType="SSODefinition"
      options={[
        'Create SAML',
        'Create OpenID',
        'Create LDAP',
        // 'Create Header',
        // 'Create ClientCert',
        // 'Create LocalAuth',
      ]}
      onOptionClick={(option) => {
        switch (option) {
          case 'Create SAML': {
            setSelectedStrategy('SAML');
            break;
          }
          case 'Create OpenID': {
            setSelectedStrategy('OpenID');
            break;
          }
          case 'Create LDAP': {
            setSelectedStrategy('LDAP');
            break;
          }
          // case 'Create Header': {
          //   setSelectedStrategy('Header');
          //   break;
          // }
          // case 'Create ClientCert': {
          //   setSelectedStrategy('ClientCert');
          //   break;
          // }
          // case 'Create LocalAuth': {
          //   setSelectedStrategy('LocalAuth');
          //   break;
          // }
          default: setSelectedStrategy(null);
        }
      }}
      {...props}
    />
  );

  const onSubmit = (
    values: SSODefinitionFormValues,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    if (!formikToSSOConfig) return;

    const configuration = formikToSSOConfig(values);

    values.advancedConfigurations.forEach((conf) => {
      if (conf.key && conf.value && conf.type) {
        configuration.push({
          key: conf.key,
          value: conf.value,
          type: conf.type,
        });
      }
    });

    const strategyEnum = getStrategyConfigEnum(selectedStrategy);

    const groups_management = {
      group_attribute: values.group_attribute || null,
      group_attributes: values.group_attributes || null,
      groups_attributes: values.groups_attributes || null,
      groups_path: values.groups_path || null,
      groups_scope: values.groups_scope || null,
      groups_mapping: getGroupOrOrganizationMapping(values.groups_mapping_source, values.groups_mapping_target),
      token_reference: values.groups_token_reference,
      read_userinfo: values.groups_read_userinfo,
    };

    const organizations_management = {
      token_reference: values.organizations_token_reference,
      organizations_path: values.organizations_path || null,
      organizations_scope: values.organizations_scope || null,
      read_userinfo: values.organizations_read_userinfo,
      organizations_mapping: getGroupOrOrganizationMapping(values.organizations_mapping_source, values.organizations_mapping_target),
    };

    const finalValues = {
      name: values.name,
      identifier: values.identifier,
      label: values.label,
      enabled: values.enabled,
      strategy: strategyEnum,
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
          ? t_i18n(`Create ${selectedStrategy} Authentication`)
          : t_i18n('Create Authentication')
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
