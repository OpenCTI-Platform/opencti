import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, DialogContentText } from '@mui/material';
import { FunctionComponent } from 'react';
import { useFormatter } from 'src/components/i18n';

interface XtmHubOriginMismatchDialogProps {
  open: boolean;
  expectedOrigin: string | null;
  receivedOrigin: string | null;
  onClose: () => void;
}

const XtmHubOriginMismatchDialog: FunctionComponent<XtmHubOriginMismatchDialogProps> = ({
  open,
  expectedOrigin,
  receivedOrigin,
  onClose,
}) => {
  const { t_i18n } = useFormatter();

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t_i18n('XTM Hub misconfiguration')}
    >
      <DialogContentText>
        {t_i18n('OpenCTI received an answer from an XTM Hub that does not match the XTM Hub URL configured on this platform. The process cannot be completed until this configuration is fixed. Please contact your platform administrator.')}
      </DialogContentText>
      <DialogContentText sx={{ marginTop: 2 }}>
        {t_i18n('Configured XTM Hub: {origin}', { values: { origin: <strong>{expectedOrigin ?? '-'}</strong> } })}
      </DialogContentText>
      <DialogContentText>
        {t_i18n('XTM Hub that answered: {origin}', { values: { origin: <strong>{receivedOrigin ?? '-'}</strong> } })}
      </DialogContentText>
      <DialogActions>
        <Button onClick={onClose}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default XtmHubOriginMismatchDialog;
