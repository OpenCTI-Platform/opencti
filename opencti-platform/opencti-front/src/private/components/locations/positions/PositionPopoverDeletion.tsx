import { graphql } from 'react-relay';
import React, { FunctionComponent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';

const PositionPopoverDeletionMutation = graphql`
  mutation PositionPopoverDeletionMutation($id: ID!) {
    positionEdit(id: $id) {
      delete
    }
  }
`;

interface PositionPopoverDeletionProps {
  positionId: string;
  handleClose: () => void;
  deletion: { deleting: boolean, handleOpenDelete: () => void, displayDelete: boolean, handleCloseDelete: () => void, setDeleting: React.Dispatch<React.SetStateAction<boolean>> };
}

const PositionPopoverDeletion: FunctionComponent<PositionPopoverDeletionProps> = ({
  positionId,
  handleClose,
  deletion,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Position') },
  });
  const [commitMutation] = useApiMutation(
    PositionPopoverDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const submitDelete = () => {
    deletion.setDeleting(true);
    commitMutation({
      variables: { id: positionId },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/positions');
      },
    });
  };
  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      message={t_i18n('Do you want to delete this position?')}
    />
  );
};

export default PositionPopoverDeletion;
