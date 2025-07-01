import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const caseRfiDeletionDeleteMutation = graphql`
  mutation CaseRfiDeletionDeleteMutation($id: ID!) {
    caseRfiDelete(id: $id)
  }
`;

const CaseRfiDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Case-Rfi') },
  });
  const [commit] = useApiMutation(
    caseRfiDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/cases/rfis');
      },
    });
  };

  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this request for information?')}
    />
  );
};

export default CaseRfiDeletion;
