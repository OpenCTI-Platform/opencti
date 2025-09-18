import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import DialogActions from '@mui/material/DialogActions';
import { CGUStatus, experienceFieldPatch } from '@components/settings/Experience';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Checkbox from '@mui/material/Checkbox';
import { FormControlLabel } from '@mui/material';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { FieldOption } from '../../../utils/field';
import useAuth from '../../../utils/hooks/useAuth';

type ValidateTermsOfUseDialogProps = {
  open: boolean;
  onClose: () => void;
};

const ValidateTermsOfUseDialog = ({ open, onClose }: ValidateTermsOfUseDialogProps) => {
  const { t_i18n } = useFormatter();
  const { settings: { id } } = useAuth();

  const [isChecked, setIsChecked] = React.useState(false);
  const [commitField] = useApiMutation(experienceFieldPatch);
  const handleSubmitField = (name: string, value: string | string[] | FieldOption | null | boolean) => {
    commitField({
      variables: {
        id,
        input: {
          key: name,
          value: ((value as FieldOption)?.value ?? value) || '',
        },
      },
    });
  };

  const updateStatus = (status?: CGUStatus.enabled | CGUStatus.disabled) => {
    if (status === CGUStatus.enabled) {
      handleSubmitField('filigran_chatbot_ai_cgu_status', CGUStatus.enabled);
    } else if (status === CGUStatus.disabled) {
      handleSubmitField('filigran_chatbot_ai_cgu_status', CGUStatus.disabled);
    }
    onClose();
  };

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
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexDirection: 'column',
          gap: 20,
        }}
      >
        <Button
          href="https://filigran.io/app/uploads/2025/09/filigran-ai-terms-september-2025.pdf"
          target="_blank"
          rel="noreferrer"
          variant="outlined"
        >
          {t_i18n('Read the Terms of Services')}
        </Button>
        <FormControlLabel
          checked={isChecked}
          required
          control={<Checkbox/>}
          label={t_i18n('I have read, understand and accept the terms and conditions')}
          labelPlacement="end"
          onChange={(_, checked) => setIsChecked(checked)}
        />
      </DialogContent>
      <DialogActions>
        <Button color="primary" onClick={() => updateStatus(CGUStatus.disabled)}>{t_i18n('Decline')}</Button>
        <Button
          color="secondary"
          onClick={() => updateStatus(CGUStatus.enabled)}
          disabled={!isChecked}
        >
          {t_i18n('I Agree to terms of services')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ValidateTermsOfUseDialog;
