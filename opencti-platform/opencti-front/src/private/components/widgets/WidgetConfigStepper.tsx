import Step from '@mui/material/Step';
import StepButton from '@mui/material/StepButton';
import StepLabel from '@mui/material/StepLabel';
import Stepper from '@mui/material/Stepper';
import React from 'react';
import { getCurrentCategory } from '../../../utils/widget/widgetUtils';
import { useFormatter } from '../../../components/i18n';
import { useWidgetConfigContext } from './WidgetConfigContext';

const WidgetConfigStepper = () => {
  const { t_i18n } = useFormatter();
  const { config, step, setStep, disabledSteps } = useWidgetConfigContext();
  const { type } = config.widget;

  const isText = getCurrentCategory(type) === 'text';
  const isAttribute = getCurrentCategory(type) === 'attribute';

  return (
    <Stepper nonLinear activeStep={step}>
      <Step>
        <StepButton
          onClick={() => setStep(0)}
          disabled={step === 0 || disabledSteps.includes(0)}
          sx={{ opacity: disabledSteps.includes(0) ? 0.4 : 1 }}
        >
          <StepLabel>{t_i18n('Visualization')}</StepLabel>
        </StepButton>
      </Step>
      <Step>
        <StepButton
          onClick={() => setStep(1)}
          disabled={step <= 1 || isText || isAttribute || disabledSteps.includes(1)}
          sx={{ opacity: isText || isAttribute || disabledSteps.includes(1) ? 0.4 : 1 }}
        >
          <StepLabel>{t_i18n('Perspective')}</StepLabel>
        </StepButton>
      </Step>
      <Step>
        <StepButton
          onClick={() => setStep(2)}
          disabled={step <= 2 || isText || isAttribute || disabledSteps.includes(2)}
          sx={{ opacity: isText || isAttribute || disabledSteps.includes(2) ? 0.4 : 1 }}
        >
          <StepLabel>{t_i18n('Filters')}</StepLabel>
        </StepButton>
      </Step>
      <Step>
        <StepButton
          onClick={() => setStep(3)}
          disabled={step <= 3 || disabledSteps.includes(3)}
          sx={{ opacity: disabledSteps.includes(3) ? 0.4 : 1 }}
        >
          <StepLabel>{t_i18n('Parameters')}</StepLabel>
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default WidgetConfigStepper;
