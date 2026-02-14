import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import Drawer, { DrawerControlledDialProps } from '../../common/drawer/Drawer';
import { insertNode } from '../../../../utils/store';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { PaginationOptions } from '../../../../components/list_lines';
import CreateSplitControlledDial from '../../../../components/CreateSplitControlledDial';
import SSODefinitionForm from '@components/settings/sso_definitions/SSODefinitionForm';
import { SingleSignOnEditInput } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';

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
  const [selectedStrategy, setSelectedStrategy] = useState<string>('');

  const CreateSSODefinitionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateSplitControlledDial
      entityType="SSODefinition"
      options={[
        'Create SAML',
        'Create OpenID',
        'Create LDAP',
        'Create ClientCert',
        'Create Header',
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
          case 'Create ClientCert': {
            setSelectedStrategy('ClientCert');
            break;
          }
          case 'Create Header': {
            setSelectedStrategy('Header');
            break;
          }
          default: setSelectedStrategy('');
        }
      }}
      {...props}
    />
  );

  const onSubmit = (
    finalValues: SingleSignOnEditInput,
    { setSubmitting, resetForm }: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
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
        setSelectedStrategy('');
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
