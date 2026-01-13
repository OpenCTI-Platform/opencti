import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import SSODefinitionForm, { SSOEditionFormInputKeys } from '@components/settings/sso_definitions/SSODefinitionForm';
import { SSODefinitionEditionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import { getConfigFromData } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';

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
    name
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
    const configurationKeyList = ['privateKey', 'providerMethod', 'issuer', 'callbackUrl', 'signingCert', 'idpCert', 'ssoBindingType', 'entryPoint'];

    const input: { key: string; value: unknown[] } = { key: field, value: [value] };

    if (configurationKeyList.includes(field)) {
      input.key = 'configuration';
      input.value = (sso.configuration ?? []).map((e) => {
        if (e.key !== field) return e;
        return { key: e.key, value: value, type: e.type };
      });
    }

    if (field === 'advancedConfigurations') {
      input.key = 'configuration';
      const config = getConfigFromData(sso.configuration ?? []);
      input.value = [...config, ...value];
    }

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
