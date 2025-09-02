import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import DialogActions from '@mui/material/DialogActions';
import { CGUStatus } from '@components/settings/Experience';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { useFormatter } from '../../../components/i18n';

type ValidateTermsOfUseDialogProps = {
  open: boolean;
  onClose: (status?: CGUStatus.enabled | CGUStatus.disabled) => void;
};

const ValidateTermsOfUseDialog = ({ open, onClose }: ValidateTermsOfUseDialogProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={open}
      onClose={() => onClose()}
      fullWidth={true}
      maxWidth="sm"
    >
      <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>{t_i18n('Validate the Terms of Services')}</div>
        <IconButton
          aria-label="Close"
          onClick={() => onClose()}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary"/>
        </IconButton>
      </DialogTitle>
      <DialogTitle>
      </DialogTitle>
      <DialogContent
        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexDirection: 'column' }}
      >
        <Button
          href="https://filigran.io/terms-of-services/"
          target="_blank"
          rel="noreferrer"
          variant="outlined"
        >
          {t_i18n('Read the Terms of Services')}
        </Button>
      </DialogContent>
      <DialogActions>
        <Button color="primary" onClick={() => onClose(CGUStatus.disabled)}>{t_i18n('Disable')}</Button>
        <Button color="secondary" onClick={() => onClose(CGUStatus.enabled)}>{t_i18n('Validate')}</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ValidateTermsOfUseDialog;
