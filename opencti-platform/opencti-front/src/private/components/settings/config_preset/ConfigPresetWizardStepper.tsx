import React, { FunctionComponent } from 'react';
import Step from '@mui/material/Step';
import StepLabel from '@mui/material/StepLabel';
import Stepper from '@mui/material/Stepper';
import { useFormatter } from '../../../../components/i18n';

const STEPS = ['Select template', 'Select items', 'Done'];

interface ConfigPresetWizardStepperProps {
  // 0: select template, 1: select items, 2: done
  activeStep: number;
}

// The three steps of the wizard (MUI: the design system has no stepper)
const ConfigPresetWizardStepper: FunctionComponent<ConfigPresetWizardStepperProps> = ({ activeStep }) => {
  const { t_i18n } = useFormatter();
  return (
    <Stepper activeStep={activeStep} alternativeLabel={false} sx={{ justifyContent: 'center' }}>
      {STEPS.map((label) => (
        <Step key={label}>
          <StepLabel>{t_i18n(label)}</StepLabel>
        </Step>
      ))}
    </Stepper>
  );
};

export default ConfigPresetWizardStepper;
