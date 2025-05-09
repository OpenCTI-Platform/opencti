import { Step, StepButton, Stepper } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../../components/i18n';

interface PirCreationFormStepperProps {
  step: number
  accessibleSteps: number[]
  onClickStep: (step: number) => void
}

const PirCreationFormStepper = ({
  step,
  accessibleSteps,
  onClickStep,
}: PirCreationFormStepperProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Stepper nonLinear activeStep={step}>
      <Step disabled={!accessibleSteps.includes(0)}>
        <StepButton color="inherit" onClick={() => onClickStep(0)}>
          {t_i18n('Priority intel type')}
        </StepButton>
      </Step>
      <Step disabled={!accessibleSteps.includes(1)}>
        <StepButton color="inherit" onClick={() => onClickStep(1)}>
          {t_i18n('General settings')}
        </StepButton>
      </Step>
      <Step disabled={!accessibleSteps.includes(2)}>
        <StepButton color="inherit" onClick={() => onClickStep(2)}>
          {t_i18n('Entities selection')}
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default PirCreationFormStepper;
