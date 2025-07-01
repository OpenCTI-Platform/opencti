import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const caseRftDeletionDeleteMutation = graphql`
  mutation CaseRftDeletionDeleteMutation($id: ID!) {
    caseRftDelete(id: $id)
  }
`;

const CaseRftDeletion = ({ id, isOpen, handleClose }: { id: string, isOpen: boolean, handleClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Case-Rft') },
  });
  const [commit] = useApiMutation(
    caseRftDeletionDeleteMutation,
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
        navigate('/dashboard/cases/rfts');
      },
    });
  };

  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this request for takedown?')}
    />
  );
};

export default CaseRftDeletion;
