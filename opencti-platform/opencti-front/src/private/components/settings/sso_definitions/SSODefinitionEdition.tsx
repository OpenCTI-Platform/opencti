import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { SSODefinitionFormValues } from '@components/settings/sso_definitions/SSODefinitionCreation';
import SSODefinitionForm from '@components/settings/sso_definitions/SSODefinitionForm';
import { SSODefinitionEditionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';

export const ssoDefinitionEditionMutation = graphql`
  mutation SSODefinitionEditionMutation($id: ID!, $input: [EditInput!]!) {
    singleSignOnFieldPatch(id: $id, input: $input) {
      ...SSODefinitionEditionFragment
    }
  }
`;

export const ssoDefinitionEditionFragment = graphql`
  fragment SSODefinitionEditionFragment on SingleSignOn {
    id
    identifier
    label
    description
    enabled
    strategy
    organizations_management {
        organizations_path
        organizations_mapping
    }
    groups_management {
        group_attributes
        groups_path
        groups_mapping
        read_userinfo
    }
    configuration {
        key
        value
        type
    }
  }
`;

interface SSODefinitionEditionProps {
  isOpen: boolean;
  onClose: () => void;
  selectedStrategy: string;
  data: SSODefinitionEditionFragment$key;
}
export type SSOEditionFormInputKeys = keyof SSODefinitionFormValues;

const SSODefinitionEdition = ({
  isOpen,
  onClose,
  data,
}: SSODefinitionEditionProps) => {
  const { t_i18n } = useFormatter();
  const sso = useFragment(ssoDefinitionEditionFragment, data);

  const [editMutation] = useApiMutation<SSODefinitionEditionMutation>(
    ssoDefinitionEditionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_SSO')} ${t_i18n('successfully updated')}` },
  );
  const selectedStrategy = sso.strategy;
  const onEdit = (field: SSOEditionFormInputKeys, value: unknown) => {
    const input: { key: string; value: [unknown] } = { key: field, value: [value] };
    editMutation({
      variables: { id: sso.id, input: [input] },
    });
  };
  const strategyConfig = selectedStrategy === 'SamlStrategy' ? 'SAML'
    : selectedStrategy === 'OpenIDConnectStrategy' ? 'OpenID'
      : selectedStrategy === 'HeaderStrategy' ? 'Header'
        : selectedStrategy === 'ClientCertStrategy' ? 'ClientCert'
          : selectedStrategy === 'LdapStrategy' ? 'Ldap'
            : selectedStrategy === 'LocalStrategy' ? 'LocalAuth' : null;
  return (
    <Drawer
      title={t_i18n(`Update a ${strategyConfig} SSO`)}
      open={isOpen}
      onClose={onClose}
    >
      <SSODefinitionForm onCancel={onClose} onSubmitField={onEdit} data={sso} selectedStrategy={strategyConfig} />
    </Drawer>
  );
};

export default SSODefinitionEdition;
