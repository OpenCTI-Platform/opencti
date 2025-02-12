import React, { FunctionComponent } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
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
  handleClose?: () => void;
}

const PositionDeletion: FunctionComponent<PositionDeletionProps> = ({
  positionId,
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
  const { setDeleting, handleOpenDelete, deleting } = deletion;
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
    <>
      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
        <Button
          color="error"
          variant="contained"
          onClick={handleOpenDelete}
          disabled={deleting}
          sx={{ marginTop: 2 }}
        >
          {t_i18n('Delete')}
        </Button>
      </Security>
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this position?')}
      />
    </>
  );
};

export default PositionDeletion;
