import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

const positionDeletionMutation = graphql`
  mutation PositionDeletionMutation($id: ID!) {
    positionEdit(id: $id) {
      delete
    }
  }
`;

interface PositionDeletionProps {
  positionId: string;
  isOpen: boolean
  handleClose: () => void;
}

const PositionDeletion: FunctionComponent<PositionDeletionProps> = ({
  positionId,
  isOpen,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Position') },
  });
  const [commitMutation] = useApiMutation(
    positionDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const deletion = useDeletion({ handleClose });
  const { setDeleting } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: positionId },
      onCompleted: () => {
        setDeleting(false);
        if (typeof handleClose === 'function') handleClose();
        navigate('/dashboard/locations/positions');
      },
    });
  };

  return (
    <DeleteDialog
      deletion={deletion}
      submitDelete={submitDelete}
      isOpen={isOpen}
      onClose={handleClose}
      message={t_i18n('Do you want to delete this position?')}
    />
  );
};

export default PositionDeletion;
