import { graphql } from 'react-relay';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import DialogContentText from '@mui/material/DialogContentText';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const PositionPopoverDeletionMutation = graphql`
  mutation PositionPopoverDeletionMutation($id: ID!) {
    positionEdit(id: $id) {
      delete
    }
  }
`;

interface PositionPopoverDeletionProps {
  positionId: string;
  displayDelete: boolean;
  handleClose: () => void;
  handleCloseDelete: () => void;
}

const PositionPopoverDeletion: FunctionComponent<PositionPopoverDeletionProps> = ({
  positionId,
  displayDelete,
  handleClose,
  handleCloseDelete,
}) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState(false);
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
    setDeleting(true);
    commitMutation({
      variables: { id: positionId },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/locations/positions');
      },
    });
  };
  return (
    <Dialog
      open={displayDelete}
      TransitionComponent={Transition}
      PaperProps={{ elevation: 1 }}
      onClose={handleCloseDelete}
    >
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this position?')}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCloseDelete} disabled={deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitDelete} disabled={deleting}>
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default PositionPopoverDeletion;
