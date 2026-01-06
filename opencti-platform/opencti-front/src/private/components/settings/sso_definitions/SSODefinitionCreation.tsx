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

  const baseInitialValues = {
    name: '',
    strategy: '',
    enabled: true,
  };
  const initialValues = {
    ...baseInitialValues,
    strategy: selectedStrategy,
  };

  const CreateSSODefinitionControlledDial = (props: DrawerControlledDialProps) => (
    <CreateSplitControlledDial
      entityType="SSODefinition"
      options={[
        'Create SAML',
        'Create OpenID',
        'Create Header',
      ]}
      onOptionClick={(option) => {
        if (option === 'Create SAML') {
          setSelectedStrategy('SAML');
        } else if (option === 'Create OpenID') {
          setSelectedStrategy('OpenID');
        } else if (option === 'Create Header') {
          setSelectedStrategy('Header');
        } else {
          setSelectedStrategy(null);
        }
      }}
      {...props}
    />
  );
  const onSubmitSAML = (
    values: SAMLCreationValues,
    { setSubmitting, resetForm }: {
      setSubmitting: (flag: boolean) => void;
      resetForm: () => void;
    },
  ) => {
    const finalValues = {
      name: values.name,
      enabled: values.enabled,
      strategy: selectedStrategy,
      configuration: [
        { key: 'ssoUrl', value: values.ssoUrl, type: 'string' },
        { key: 'entityId', value: values.entityId, type: 'string' },
        // autres champs SAML
      ],
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
      title={t_i18n(`Create ${selectedStrategy} SSO`)}
      controlledDial={CreateSSODefinitionControlledDial}
    >
      {({ onClose }) => {
        if (selectedStrategy === 'SAML') {
          return (
            <SAMLCreation
              initialValues={initialValues}
              onSubmit={onSubmitSAML}
              onCancel={() => {
                onClose();
              }}
            />
          );
        }
        return (
          <> </>
        );
      }}
    </Drawer>
  );
};
export default SSODefinitionCreation;
