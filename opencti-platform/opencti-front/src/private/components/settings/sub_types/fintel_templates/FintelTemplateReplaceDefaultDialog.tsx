import { DialogActions, Typography } from '@mui/material';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../../components/i18n';

interface FintelTemplateReplaceDefaultDialogProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  currentDefaultName: string;
}

const FintelTemplateReplaceDefaultDialog = ({
  open,
  onClose,
  onConfirm,
  currentDefaultName,
}: FintelTemplateReplaceDefaultDialogProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t_i18n('Replace default template?')}
      size="small"
    >
      <Typography>
        {t_i18n('The template {name} is currently set as default. Do you want to replace it?', {
          values: { name: <strong>{currentDefaultName}</strong> },
        })}
      </Typography>
      <DialogActions>
        <Button variant="secondary" onClick={onClose}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={onConfirm}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default FintelTemplateReplaceDefaultDialog;
