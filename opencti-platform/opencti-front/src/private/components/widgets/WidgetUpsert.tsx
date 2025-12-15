import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent } from 'react';
import WidgetConfigStepper from './WidgetConfigStepper';
import { useWidgetConfigContext, WidgetConfigType } from './WidgetConfigContext';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';
import WidgetCreationTypes from './WidgetCreationTypes';
import WidgetCreationPerspective from './WidgetCreationPerspective';
import WidgetCreationDataSelection from './WidgetCreationDataSelection';
import WidgetCreationParameters from './WidgetCreationParameters';
import useWidgetConfigValidateForm from './useWidgetConfigValidateForm';

interface WidgetUpsertProps {
  open: boolean;
  onCancel: () => void;
  onSubmit: (conf: WidgetConfigType) => void;
  isUpdate: boolean;
}

const WidgetUpsert: FunctionComponent<WidgetUpsertProps> = ({
  open,
  onCancel,
  onSubmit,
  isUpdate,
}) => {
  const { t_i18n } = useFormatter();
  const { config, step } = useWidgetConfigContext();
  const { isFormValid } = useWidgetConfigValidateForm();

  return (
    <Dialog
      open={open}
      slotProps={{ paper: { elevation: 1 } }}
      slots={{ transition: Transition }}
      onClose={onCancel}
      fullWidth={true}
      maxWidth="md"
      className="noDrag"
    >
      <DialogTitle>
        <WidgetConfigStepper />
      </DialogTitle>

      {open && (
        <DialogContent>
          {step === 0 && <WidgetCreationTypes />}
          {step === 1 && <WidgetCreationPerspective />}
          {step === 2 && <WidgetCreationDataSelection />}
          {step === 3 && <WidgetCreationParameters />}
        </DialogContent>
      )}

      <DialogActions>
        <Button variant="secondary" onClick={onCancel}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          data-testid="widget-submit-button"
          onClick={() => onSubmit(config)}
          disabled={!isFormValid}
        >
          {isUpdate ? t_i18n('Update') : t_i18n('Create')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WidgetUpsert;
