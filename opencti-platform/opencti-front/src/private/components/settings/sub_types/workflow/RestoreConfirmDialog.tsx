import { DialogActions } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../../components/i18n';

interface RestoreConfirmDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
}

const RestoreConfirmDialog = ({ open, onClose, onConfirm }: RestoreConfirmDialogProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t_i18n('Restore published version')}
      size="small"
    >
      {t_i18n('This will replace the workflow with the last published version. All unpublished changes will be lost. Are you sure?')}
      <DialogActions>
        <Button
          variant="secondary"
          onClick={onClose}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          intent="destructive"
          onClick={onConfirm}
        >
          {t_i18n('Restore')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default RestoreConfirmDialog;
