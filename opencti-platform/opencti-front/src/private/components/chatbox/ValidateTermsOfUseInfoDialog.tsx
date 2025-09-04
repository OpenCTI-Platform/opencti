import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import DialogActions from '@mui/material/DialogActions';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import useGranted, { SETTINGS_SETACCESSES } from '../../../utils/hooks/useGranted';

type ValidateTermsOfUseInfoDialogProps = {
  open: boolean;
  onClose: () => void;
};

const ValidateTermsOfUseInfoDialog = ({ open, onClose }: ValidateTermsOfUseInfoDialogProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const hasRightToValidateCGU = useGranted([SETTINGS_SETACCESSES]);
  return (
    <Dialog
      slotProps={{ paper: { elevation: 1 } }}
      open={open}
      onClose={onClose}
      fullWidth={true}
      maxWidth="sm"
    >
      <DialogTitle>
        {t_i18n('Enable Ask Ariane')}
      </DialogTitle>
      <DialogContent>
        {hasRightToValidateCGU
          ? t_i18n('Only an administrator with access to Filigran Experience settings can accept the Terms of Services and activate them in Settings.')
          : t_i18n('Please contact your administrator to accept the Terms of Services and activate Ask Ariane.')
        }
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t_i18n('Cancel')}</Button>
        {hasRightToValidateCGU && (
          <Button color="secondary"
            onClick={() => {
              navigate('/dashboard/settings/experience');
              onClose();
            }}
          >
            {t_i18n('Go to settings')}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default ValidateTermsOfUseInfoDialog;
