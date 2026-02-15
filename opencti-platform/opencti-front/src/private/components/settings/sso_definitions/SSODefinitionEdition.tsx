import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import SSODefinitionForm from '@components/settings/sso_definitions/SSODefinitionForm';
import SSODefinitionDeletion from '@components/settings/sso_definitions/SSODefinitionDeletion';
import { SSODefinitionEditionFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionFragment.graphql';
import { SingleSignOnEditInput, SSODefinitionEditionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionEditionMutation.graphql';
import { getStrategyConfigSelected } from '@components/settings/sso_definitions/utils/useStrategicConfig';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import IconButton from '@mui/material/IconButton';
import DeleteOutlined from '@mui/icons-material/DeleteOutlined';

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
  data: SSODefinitionEditionFragment$key;
  paginationOptions?: Record<string, unknown>;
}

const SSODefinitionEdition = ({
  isOpen,
  onClose,
  data,
  paginationOptions,
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

  const strategyConfigSelected = getStrategyConfigSelected(sso.strategy);

  return (
    <Drawer
      title={t_i18n(`Update a ${strategyConfigSelected} Authentication`)}
      open={isOpen}
      onClose={onClose}
      header={(
        <SSODefinitionDeletion
          ssoId={sso.id}
          paginationOptions={paginationOptions}
          onDeleteComplete={onClose}
        >
          {({ handleOpenDelete, deleting }) => (
            <IconButton
              onClick={handleOpenDelete}
              disabled={deleting}
              color="error"
              size="small"
              aria-label={t_i18n('Delete')}
            >
              <DeleteOutlined fontSize="small" />
            </IconButton>
          )}
        </SSODefinitionDeletion>
      )}
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
