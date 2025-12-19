import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React, { UIEvent } from 'react';
import DialogTitle from '@mui/material/DialogTitle';
import Alert from '@mui/material/Alert';
import { AlertTitle } from '@mui/material';
import Transition from './Transition';
import { useFormatter } from './i18n';
import { Deletion } from '../utils/hooks/useDeletion';

type DeleteDialogProps = {
  deletion: Deletion;
  submitDelete: (e: UIEvent) => void;
  onClose?: () => void;
  message: React.ReactNode;
  warning?: {
    title?: string;
    message: string;
  };
  isOpen?: boolean;
};

const DeleteDialog: React.FC<DeleteDialogProps> = ({
  deletion,
  submitDelete,
  onClose,
  message,
  warning,
  isOpen,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog
      open={isOpen ?? deletion.displayDelete}
      slotProps={{ paper: { elevation: 1 } }}
      keepMounted={true}
      slots={{ transition: Transition }}
      onClose={onClose ?? ((e) => deletion.handleCloseDelete(e as UIEvent))}
    >
      <DialogTitle>
        {t_i18n('Are you sure?')}
      </DialogTitle>
      <DialogContent>
        <DialogContentText>{message}</DialogContentText>
        {warning && (
          <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
            <AlertTitle>{warning.title}</AlertTitle>
            {warning.message}
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={onClose ?? deletion.handleCloseDelete} disabled={deletion.deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={submitDelete} disabled={deletion.deleting}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DeleteDialog;
