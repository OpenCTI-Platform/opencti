import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import { FunctionComponent } from 'react';
import { useFormatter } from '../../../components/i18n';
import { useWidgetConfigContext, WidgetConfigType } from './WidgetConfigContext';
import WidgetConfigStepper from './WidgetConfigStepper';
import WidgetCreationDataSelection from './WidgetCreationDataSelection';
import WidgetCreationParameters from './WidgetCreationParameters';
import WidgetCreationPerspective from './WidgetCreationPerspective';
import WidgetCreationTypes from './WidgetCreationTypes';
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
      onClose={onCancel}
      className="noDrag"
    >
      <WidgetConfigStepper />

      {open && (
        <>
          {step === 0 && <WidgetCreationTypes />}
          {step === 1 && <WidgetCreationPerspective />}
          {step === 2 && <WidgetCreationDataSelection />}
          {step === 3 && <WidgetCreationParameters />}
        </>
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
