import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, DialogContentText } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../../../../components/i18n';

interface Props {
  open: boolean;
  onCancel: () => void;
}

const XtmHubDialogConnectivityLostUnauthorizedRegister: React.FC<Props> = ({ open, onCancel }) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog
      open={open}
      onClose={onCancel}
      slotProps={{ paper: { elevation: 1 } }}
      aria-labelledby="unauthorized-register-dialog-title"
      aria-describedby="unauthorized-register-dialog-description"
      title={
        <span id="unauthorized-register-dialog-title">{t_i18n('Connectivity lost')}</span>
      }
    >
      <DialogContentText id="unauthorized-register-dialog-description">
        <p>{t_i18n('XTM Hub Connection Unavailable')}</p>
        <p>{t_i18n('Please contact OpenCTI platform admin')}</p>
      </DialogContentText>
      <DialogActions>
        <Button onClick={onCancel}>
          {t_i18n('Cancel')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default XtmHubDialogConnectivityLostUnauthorizedRegister;
