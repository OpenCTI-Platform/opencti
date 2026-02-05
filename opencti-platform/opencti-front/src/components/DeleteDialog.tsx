import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { AlertTitle, DialogActions, Typography } from '@mui/material';
import Alert from '@mui/material/Alert';
import React, { UIEvent } from 'react';
import { Deletion } from '../utils/hooks/useDeletion';
import { useFormatter } from './i18n';

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
      onClose={onClose ?? ((e) => deletion.handleCloseDelete(e as UIEvent))}
      title={t_i18n('Are you sure?')}
      size="small"
    >
      <Typography>{message}</Typography>
      {warning && (
        <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
          <AlertTitle>{warning.title}</AlertTitle>
          {warning.message}
        </Alert>
      )}
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
