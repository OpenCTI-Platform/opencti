import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions, DialogContentText } from '@mui/material';
import { FunctionComponent, useEffect, useState } from 'react';
import { useFormatter } from 'src/components/i18n';
import { XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY } from '../../RedirectByPath';

const XtmHubPermissionRequiredDialog: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    if (sessionStorage.getItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY) !== 'true') {
      return;
    }
    setIsOpen(true);
    sessionStorage.removeItem(XTM_HUB_PERMISSION_REQUIRED_DIALOG_SESSION_STORAGE_KEY);
  }, []);

  return (
    <Dialog
      open={isOpen}
      onClose={() => setIsOpen(false)}
      title={t_i18n('Permission required')}
    >
      <DialogContentText>
        {t_i18n('You do not have permission to connect this product. Please contact your product administrator to connect the product on your behalf.')}
      </DialogContentText>
      <DialogActions>
        <Button onClick={() => setIsOpen(false)}>
          {t_i18n('Close')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default XtmHubPermissionRequiredDialog;
