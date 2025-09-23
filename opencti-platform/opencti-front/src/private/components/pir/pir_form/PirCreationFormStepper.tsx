/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import { Step, StepButton, Stepper } from '@mui/material';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';

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
          {t_i18n('General settings')}
        </StepButton>
      </Step>
      <Step disabled={!accessibleSteps.includes(1)}>
        <StepButton color="inherit" onClick={() => onClickStep(1)}>
          {t_i18n('Entities selection')}
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default PirCreationFormStepper;
