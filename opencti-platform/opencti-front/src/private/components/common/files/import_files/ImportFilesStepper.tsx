import { Step, StepButton, Stepper } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../../../../components/i18n';

interface ImportFilesStepperProps {
  activeStep: number;
  setActiveStep: (step: number) => void;
}

const ImportFilesStepper = ({ activeStep, setActiveStep }: ImportFilesStepperProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Stepper nonLinear activeStep={activeStep} sx={{ marginInline: 10 }}>
      <Step key={'select_file'}>
        <StepButton color="inherit" onClick={() => setActiveStep(0)}>
          { t_i18n('Select files') }
        </StepButton>
      </Step>
      <Step key={'import_options'}>
        <StepButton color="inherit" onClick={() => setActiveStep(1)}>
          { t_i18n('Import options') }
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default ImportFilesStepper;
