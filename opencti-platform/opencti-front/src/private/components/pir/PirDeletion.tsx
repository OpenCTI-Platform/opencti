import { graphql } from 'react-relay';
import React, { ReactNode, UIEvent } from 'react';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { PirDeletionMutation } from './__generated__/PirDeletionMutation.graphql';
import useDeletion from '../../../utils/hooks/useDeletion';
import stopEvent from '../../../utils/domEvent';
import DeleteDialog from '../../../components/DeleteDialog';

const pirDeleteMutation = graphql`
  mutation PirDeletionMutation($id: ID!) {
    pirDelete(id: $id)
  }
`;

interface ChildrenProps {
  handleOpenDelete: (e?: UIEvent) => void
  deleting: boolean
}

interface PirDeletionProps {
  pirId: string
  onDeleteComplete?: () => void
  children: (props: ChildrenProps) => ReactNode
}

const PirDeletion = ({ pirId, onDeleteComplete, children }: PirDeletionProps) => {
  const { t_i18n } = useFormatter();

  const [deleteMutation, deleting] = useApiMutation<PirDeletionMutation>(
    pirDeleteMutation,
    undefined,
    { successMessage: `${t_i18n('entity_Pir')} ${t_i18n('successfully deleted')}` },
  );

  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

  const onDelete = (e: UIEvent) => {
    stopEvent(e);
    deleteMutation({
      variables: { id: pirId },
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
        message={t_i18n('Do you want to delete this PIR?')}
      />
    </>
  );
};

export default PirDeletion;
