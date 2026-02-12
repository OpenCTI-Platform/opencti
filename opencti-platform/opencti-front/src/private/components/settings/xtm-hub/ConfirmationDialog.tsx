import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, DialogContentText } from '@mui/material';
import { FunctionComponent } from 'react';

interface ConfirmationDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmButtonText?: string;
  cancelButtonText?: string;
  onConfirm: () => void;
  onCancel: () => void;
}

const ConfirmationDialog: FunctionComponent<ConfirmationDialogProps> = ({
  open,
  title,
  message,
  confirmButtonText = 'Confirm',
  cancelButtonText = 'Cancel',
  onConfirm,
  onCancel,
}) => {
  return (
    <Dialog
      open={open}
      onClose={onCancel}
      aria-labelledby="confirmation-dialog-title"
      aria-describedby="confirmation-dialog-description"
      title={
        <span id="confirmation-dialog-title">{title}</span>
      }
    >
      <DialogContentText id="confirmation-dialog-description">
        {message}
      </DialogContentText>
      <DialogActions>
        <Button variant="secondary" onClick={onCancel} color="primary">
          {cancelButtonText}
        </Button>
        <Button onClick={onConfirm} color="error" autoFocus>
          {confirmButtonText}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ConfirmationDialog;
