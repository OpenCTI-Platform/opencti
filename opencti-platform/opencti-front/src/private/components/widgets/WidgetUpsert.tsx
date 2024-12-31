import DialogTitle from '@mui/material/DialogTitle';
import Stepper from '@mui/material/Stepper';
import Step from '@mui/material/Step';
import StepButton from '@mui/material/StepButton';
import StepLabel from '@mui/material/StepLabel';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent, ReactNode } from 'react';
import Transition from '../../../components/Transition';
import { useFormatter } from '../../../components/i18n';
import { getCurrentAvailableParameters, getCurrentCategory } from './widgetUtils';
import type { Widget } from '../../../utils/widget/widget';

interface WidgetUpsertProps {
  open: boolean,
  handleCloseAfterCancel: () => void,
  stepIndex: number,
  setStepIndex: (n: number) => void,
  getStepContent: () => ReactNode | string,
  completeSetup: () => void,
  isDataSelectionAttributesValid: () => boolean,
  widget?: Widget,
  type: string | null,
}

const WidgetUpsert: FunctionComponent<WidgetUpsertProps> = ({
  open,
  handleCloseAfterCancel,
  stepIndex,
  setStepIndex,
  getStepContent,
  completeSetup,
  isDataSelectionAttributesValid,
  widget,
  type,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog
      open={open}
      PaperProps={{ elevation: 1 }}
      TransitionComponent={Transition}
      onClose={handleCloseAfterCancel}
      fullWidth={true}
      maxWidth="md"
      className="noDrag"
    >
      <DialogTitle>
        <Stepper nonLinear activeStep={stepIndex}>
          <Step>
            <StepButton
              onClick={() => setStepIndex(0)}
              disabled={stepIndex === 0}
            >
              <StepLabel>{t_i18n('Visualization')}</StepLabel>
            </StepButton>
          </Step>
          <Step>
            <StepButton
              onClick={() => setStepIndex(1)}
              disabled={stepIndex <= 1 || getCurrentCategory(type) === 'text'}
            >
              <StepLabel>{t_i18n('Perspective')}</StepLabel>
            </StepButton>
          </Step>
          <Step>
            <StepButton
              onClick={() => setStepIndex(2)}
              disabled={stepIndex <= 2 || getCurrentCategory(type) === 'text'}
            >
              <StepLabel>{t_i18n('Filters')}</StepLabel>
            </StepButton>
          </Step>
          <Step>
            <StepButton
              onClick={() => setStepIndex(3)}
              disabled={stepIndex <= 3}
            >
              <StepLabel>{t_i18n('Parameters')}</StepLabel>
            </StepButton>
          </Step>
        </Stepper>
      </DialogTitle>
      <DialogContent>{getStepContent()}</DialogContent>
      <DialogActions>
        <Button onClick={handleCloseAfterCancel}>{t_i18n('Cancel')}</Button>
        <Button
          color="secondary"
          onClick={completeSetup}
          disabled={
            stepIndex !== 3
            || (getCurrentAvailableParameters(type).includes('attribute')
              && !isDataSelectionAttributesValid())
          }
          data-testid="widget-submit-button"
        >
          {widget ? t_i18n('Update') : t_i18n('Create')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default WidgetUpsert;
