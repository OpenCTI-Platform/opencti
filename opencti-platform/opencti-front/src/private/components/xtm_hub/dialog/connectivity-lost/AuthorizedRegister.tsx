import React from 'react';
import { Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle } from '@mui/material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';

interface Props {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

const XtmHubDialogConnectivityLostAuthorizedRegister: React.FC<Props> = ({ open, onCancel, onConfirm }) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog
      open={open}
      onClose={onCancel}
      slotProps={{ paper: { elevation: 1 } }}
      aria-labelledby="authorized-register-dialog-title"
      aria-describedby="authorized-register-dialog-description"
    >
      <DialogTitle id="authorized-register-dialog-title">{t_i18n('Connectivity lost')}</DialogTitle>
      <DialogContent>
        <DialogContentText id="authorized-register-dialog-description">
          <p>{t_i18n('XTM Hub Connection Unavailable')}</p>
          <p>{t_i18n('Please re-register platform')}</p>
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={onCancel} color="primary">
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={onConfirm}>
          {t_i18n('Re-register')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default XtmHubDialogConnectivityLostAuthorizedRegister;
