import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import Transition from './Transition';
import { useFormatter } from './i18n';
import { Deletion } from '../utils/hooks/useDeletion';
import DialogTitle from '@mui/material/DialogTitle';
import Alert from '@mui/material/Alert';
import { AlertTitle } from '@mui/material';

type DeleteDialogProps = {
  message?: React.ReactNode
  deletion: Deletion
  submitDelete: () => void
  onClose?: () => void
  alertTitle?: React.ReactNode
};

const DeleteDialog: React.FC<DeleteDialogProps> = ({
  message,
  deletion,
  submitDelete,
  onClose,
  alertTitle,
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
      <DialogTitle>
        {t_i18n('Are you sure?')}
      </DialogTitle>
      <DialogContent>
        {alertTitle ? (
          <Alert severity="warning" variant="outlined">
            <AlertTitle>{alertTitle}</AlertTitle>
            {message}
          </Alert>
        ) : (
          <DialogContentText>{message}</DialogContentText>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose ?? deletion.handleCloseDelete} disabled={deletion.deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitDelete} disabled={deletion.deleting}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DeleteDialog;
