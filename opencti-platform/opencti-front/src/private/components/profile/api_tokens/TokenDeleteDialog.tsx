import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, DialogContentText } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';

interface TokenDeleteDialogProps {
  open: boolean;
  token: { id: string; name: string } | null;
  onClose: () => void;
  onDelete: () => void;
}

const TokenDeleteDialog = ({ open, token, onDelete, onClose }: TokenDeleteDialogProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      aria-labelledby="alert-dialog-title"
      aria-describedby="alert-dialog-description"
      title={t_i18n('Revoke API Token')}
      size="small"
    >
      <DialogContentText id="alert-dialog-description">
        {t_i18n('Do you want to revoke the token')} <strong>{token?.name}</strong>?
      </DialogContentText>
      <DialogActions>
        <Button
          variant="secondary"
          onClick={onClose}
        >
          {t_i18n('Cancel')}
        </Button>
        <Button
          intent="destructive"
          onClick={onDelete}
          autoFocus
        >
          {t_i18n('Revoke')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default TokenDeleteDialog;
