import { Step, StepButton, Stepper } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';

interface SecurityCoverageResultFormStepsProps {
  activeStep: number;
  onStepClick: (step: number) => void;
}

const SecurityCoverageResultFormSteps = ({
  activeStep,
  onStepClick,
}: SecurityCoverageResultFormStepsProps) => {
  const { t_i18n } = useFormatter();

  const stepDisabled = (step: number) => {
    return step >= activeStep;
  };

  return (
    <Stepper activeStep={activeStep}>
      <Step disabled={stepDisabled(0)}>
        <StepButton onClick={() => onStepClick(0)}>
          {t_i18n('Coverage Result details')}
        </StepButton>
      </Step>
      <Step disabled={stepDisabled(1)}>
        <StepButton onClick={() => onStepClick(1)}>
          {t_i18n('Select entities to test coverage')}
        </StepButton>
      </Step>
      <Step disabled={stepDisabled(2)}>
        <StepButton>
          {t_i18n('Add coverage scores to relationships')}
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default SecurityCoverageResultFormSteps;
