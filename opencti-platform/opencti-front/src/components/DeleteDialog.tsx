import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import Transition from './Transition';
import { useFormatter } from './i18n';
import { Deletion } from '../utils/hooks/useDeletion';

const DeleteDialog = ({
  title,
  deletion,
  submitDelete,
}: {
  title: string
  deletion: Deletion
  submitDelete: () => void
}) => {
  const { t } = useFormatter();

  return (
    <Dialog
      open={deletion.displayDelete}
      PaperProps={{ elevation: 1 }}
      keepMounted={true}
      TransitionComponent={Transition}
      onClose={deletion.handleCloseDelete}
    >
      <DialogContent>
        <DialogContentText>
          {title}
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={deletion.handleCloseDelete} disabled={deletion.deleting}>
          {t('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitDelete} disabled={deletion.deleting}>
          {t('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DeleteDialog;
