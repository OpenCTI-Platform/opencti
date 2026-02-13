import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SSODefinitionForm from '@components/settings/sso_definitions/SSODefinitionForm';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import { SingleSignOnEditInput, SSODefinitionEditionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import { getStrategyConfigSelected } from '@components/settings/sso_definitions/utils/useStrategicConfig';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const ssoDefinitionEditionMutation = graphql`
    mutation SSODefinitionEditionMutation($id: ID!, $input: SingleSignOnEditInput!) {
        singleSignOnEdit(id: $id, input: $input) {
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
      organizations_scope
      read_userinfo
      token_reference
    }
    groups_management {
      group_attribute
      group_attributes
      groups_attributes
      groups_path
      groups_scope
      groups_mapping
      read_userinfo
      token_reference
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

  const onSubmit = (
    finalValues: SingleSignOnEditInput,
    { setSubmitting, resetForm}: { setSubmitting: (flag: boolean) => void; resetForm: () => void },
  ) => {
    setSubmitting(true);
    editMutation({
      variables: { id: sso.id, input: finalValues },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
      },
    });
  };

  const strategyConfigSelected = getStrategyConfigSelected(selectedStrategy);

  return (
    <Drawer
      title={t_i18n(`Update a ${strategyConfigSelected} Authentication`)}
      open={isOpen}
      onClose={onClose}
    >
      <SSODefinitionForm
        onCancel={onClose}
        onSubmit={onSubmit}
        data={sso}
        selectedStrategy={strategyConfigSelected}
        isEditing
      />
    </Drawer>
  );
};

export default SSODefinitionEdition;
