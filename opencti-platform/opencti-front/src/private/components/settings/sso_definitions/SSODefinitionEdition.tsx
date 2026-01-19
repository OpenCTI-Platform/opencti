import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import SSODefinitionForm, { SSOEditionFormInputKeys } from '@components/settings/sso_definitions/SSODefinitionForm';
import { SSODefinitionEditionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import { getConfigFromData, getSSOConfigList } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';
import { getStrategyConfigSelected } from '@components/settings/sso_definitions/utils/useStrategicConfig';

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
        group_attribute
        group_attributes
        groups_attributes
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
  selectedStrategy,
}: SSODefinitionEditionProps) => {
  const { t_i18n } = useFormatter();
  const sso = useFragment(ssoDefinitionEditionFragment, data);

  const [editMutation] = useApiMutation<SSODefinitionEditionMutation>(
    ssoDefinitionEditionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_SSO')} ${t_i18n('successfully updated')}` },
  );

  const onEdit = (field: SSOEditionFormInputKeys, value: unknown) => {
    const configurationKeyList = getSSOConfigList(selectedStrategy ?? '');
    const groupManagementKeyList = ['group_attribute', 'groups_attributes', 'group_attributes', 'groups_path', 'groups_mapping'];
    const organizationsManagementKeyList = ['organizations_path', 'organizations_mapping'];

    const input: { key: string; value: unknown[] } = { key: field, value: [value] };

    if (configurationKeyList.includes(field)) {
      input.key = 'configuration';
      input.value = (sso.configuration ?? []).map((e) => {
        if (e.key !== field) return e;
        const newValue = Array.isArray(value) ? JSON.stringify(value) : value;
        return { key: e.key, value: newValue, type: e.type };
      });
    }

    if (field === 'advancedConfigurations') {
      input.key = 'configuration';
      const config = getConfigFromData(sso.configuration ?? [], selectedStrategy ?? '');
      input.value = Array.isArray(value) ? [...config, ...value] : [...config];
    }

    if (groupManagementKeyList.includes(field)) {
      input.key = 'groups_management';
      input.value = [{
        ...sso.groups_management,
        [field]: Array.isArray(value) ? value : [value],
      }];
    }

    if (organizationsManagementKeyList.includes(field)) {
      input.key = 'organizations_management';
      input.value = [{
        ...sso.organizations_management,
        [field]: Array.isArray(value) ? value : [value],
      }];
    }

    editMutation({
      variables: { id: sso.id, input: [input] },
    });
  };

  const strategyConfigSelected = getStrategyConfigSelected(selectedStrategy);

  return (
    <Drawer
      title={t_i18n(`Update a ${strategyConfigSelected} SSO`)}
      open={isOpen}
      onClose={onClose}
    >
      <SSODefinitionForm onCancel={onClose} onSubmitField={onEdit} data={sso} selectedStrategy={strategyConfigSelected} />
    </Drawer>
  );
};

export default SSODefinitionEdition;
