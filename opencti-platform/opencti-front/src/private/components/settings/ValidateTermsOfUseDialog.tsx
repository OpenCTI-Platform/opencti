import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React from 'react';
import DialogActions from '@mui/material/DialogActions';
import { CGUStatus, experienceFieldPatch } from '@components/settings/Experience';
import IconButton from '@common/button/IconButton';
import { Close } from '@mui/icons-material';
import Checkbox from '@mui/material/Checkbox';
import { FormControlLabel } from '@mui/material';
import Typography from '@mui/material/Typography';
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
        {t_i18n('Validate the Filigran AI Terms')}
        <IconButton
          aria-label="Close"
          onClick={() => onClose()}
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
      </DialogTitle>
      <DialogContent
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 20,
        }}
      >
        <Typography>
          {t_i18n('Please take a moment to review our "Filigran AI Terms". Our chatbot is here to assist you, but it\'s important to understand how it works and what to expect. Please read the full terms to know how we protect your data and ensure service quality.')}
        </Typography>
        <div style={{ textAlign: 'center' }}>
          <Button
            href="https://filigran.io/app/uploads/2025/09/filigran-ai-terms-september-2025.pdf"
            target="_blank"
            rel="noreferrer"
            variant="secondary"
            style={{ width: 'fit-content' }}
          >
            {t_i18n('Read the Filigran AI Terms')}
          </Button>
        </div>
        <FormControlLabel
          checked={isChecked}
          required
          control={<Checkbox />}
          label={t_i18n('I have read, I understand and I accept the Filigran AI terms')}
          labelPlacement="end"
          onChange={(_, checked) => setIsChecked(checked)}
        />
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={() => updateStatus(CGUStatus.disabled)}>{t_i18n('Decline')}</Button>
        <Button
          onClick={() => updateStatus(CGUStatus.enabled)}
          disabled={!isChecked}
        >
          {t_i18n('I Agree to Filigran AI Terms')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ValidateTermsOfUseDialog;
