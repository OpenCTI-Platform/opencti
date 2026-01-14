import { graphql } from 'react-relay';
import React, { ReactNode, UIEvent } from 'react';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import stopEvent from '../../../../utils/domEvent';
import DeleteDialog from '../../../../components/DeleteDialog';
import { SSODefinitionDeletionMutation } from '@components/settings/sso_definitions/__generated__/SSODefinitionDeletionMutation.graphql';

const ssoDefinitionDeletionMutation = graphql`
    mutation SSODefinitionDeletionMutation($id: ID!) {
        singleSignOnDelete(id: $id)
    }
`;

interface ChildrenProps {
  handleOpenDelete: (e?: UIEvent) => void;
  deleting: boolean;
}

interface SSODefinitionDeletionProps {
  ssoId: string;
  onDeleteComplete?: () => void;
  children: (props: ChildrenProps) => ReactNode;
}

const SSODefinitionDeletion = ({ ssoId, onDeleteComplete, children }: SSODefinitionDeletionProps) => {
  const { t_i18n } = useFormatter();

  const [deleteMutation, deleting] = useApiMutation<SSODefinitionDeletionMutation>(
    ssoDefinitionDeletionMutation,
    undefined,
    { successMessage: `${t_i18n('entity_SSO')} ${t_i18n('successfully deleted')}` },
  );

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    deleteMutation({
      variables: { id: ssoId },
      onCompleted: () => {
        handleCloseDelete();
        onDeleteComplete?.();
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <>
      {children({ handleOpenDelete, deleting })}
      <DeleteDialog
        deletion={deletion}
        submitDelete={onDelete}
        message={t_i18n('Do you want to delete this SSO?')}
      />
    </>
  );
};

export default SSODefinitionDeletion;
