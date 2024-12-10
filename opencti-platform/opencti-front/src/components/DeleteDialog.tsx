import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import Transition from './Transition';
import { useFormatter } from './i18n';
import { Deletion } from '../utils/hooks/useDeletion';

type DeleteDialogProps = {
  title: React.ReactNode
  deletion: Deletion
  submitDelete: () => void
  onClose?: () => void
};

const DeleteDialog: React.FC<DeleteDialogProps> = ({
  title,
  deletion,
  submitDelete,
  onClose,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog
      open={deletion.displayDelete}
      PaperProps={{ elevation: 1 }}
      keepMounted={true}
      TransitionComponent={Transition}
      onClose={onClose ?? deletion.handleCloseDelete}
    >
      <DialogContent>
        <DialogContentText>
          {title}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose ?? deletion.handleCloseDelete} disabled={deletion.deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitDelete} disabled={deletion.deleting}>
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DeleteDialog;
