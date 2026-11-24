import React from 'react';
import { useNavigate } from 'react-router';
import { graphql } from 'react-relay';
import { PATH_PROCEDURES } from '@components/common/routes/paths';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { MESSAGING$ } from '../../../../relay/environment';
import DeleteDialog from '../../../../components/DeleteDialog';

const ProcedureDeletionDeleteMutation = graphql`
  mutation ProcedureDeletionDeleteMutation($id: ID!) {
    procedureDelete(id: $id)
  }
`;

const ProcedureDeletion = ({ id, isOpen, handleClose }: { id: string; isOpen: boolean; handleClose: () => void }) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const deleteSuccessMessage = t_i18n('{entity_type} successfully deleted', {
    values: { entity_type: t_i18n('entity_Procedure') },
  });
  const [commit] = useApiMutation(
    ProcedureDeletionDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate(PATH_PROCEDURES);
      },
      onError: (error) => {
        MESSAGING$.notifyRelayError(error);
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this procedure?')}
    />
  );
};

export default ProcedureDeletion;
