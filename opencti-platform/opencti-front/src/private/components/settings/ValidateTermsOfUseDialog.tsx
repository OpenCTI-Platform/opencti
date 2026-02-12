import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { CGUStatus, experienceFieldPatch } from '@components/settings/Experience';
import { DialogActions, FormControlLabel, Stack } from '@mui/material';
import Checkbox from '@mui/material/Checkbox';
import Typography from '@mui/material/Typography';
import React from 'react';
import { useFormatter } from '../../../components/i18n';
import { FieldOption } from '../../../utils/field';
import useApiMutation from '../../../utils/hooks/useApiMutation';
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
      open={open}
      onClose={onClose}
      title={t_i18n('Validate the Filigran AI Terms')}
      showCloseButton
    >
      <Stack gap={3}>
        <Typography>
          {t_i18n('Please take a moment to review our "Filigran AI Terms". Our chatbot is here to assist you, but it\'s important to understand how it works and what to expect. Please read the full terms to know how we protect your data and ensure service quality.')}
        </Typography>

        <Stack alignItems="center" gap={2}>
          <Button
            href="https://filigran.io/app/uploads/2025/09/filigran-ai-terms-september-2025.pdf"
            target="_blank"
            rel="noreferrer"
            variant="secondary"
          >
            {t_i18n('Read the Filigran AI Terms')}
          </Button>

          <FormControlLabel
            checked={isChecked}
            required
            control={<Checkbox />}
            label={t_i18n('I have read, I understand and I accept the Filigran AI terms')}
            labelPlacement="end"
            onChange={(_, checked) => setIsChecked(checked)}
          />
        </Stack>

        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => updateStatus(CGUStatus.disabled)}
          >
            {t_i18n('Decline')}
          </Button>
          <Button
            onClick={() => updateStatus(CGUStatus.enabled)}
            disabled={!isChecked}
          >
            {t_i18n('I Agree to Filigran AI Terms')}
          </Button>
        </DialogActions>
      </Stack>
    </Dialog>
  );
};

export default ValidateTermsOfUseDialog;
