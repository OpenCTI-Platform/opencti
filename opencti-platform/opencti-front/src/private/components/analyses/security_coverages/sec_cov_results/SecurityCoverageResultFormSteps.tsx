import { Step, StepButton, Stepper } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';

interface SecurityCoverageResultFormStepsProps {
  activeStep: number;
  onStepClick: (step: number) => void;
  isUpdate?: boolean;
}

const SecurityCoverageResultFormSteps = ({
  activeStep,
  onStepClick,
  isUpdate = false,
}: SecurityCoverageResultFormStepsProps) => {
  const { t_i18n } = useFormatter();

  const steps = [
    ...(isUpdate ? ['Select security coverage result to update'] : []),
    'Coverage Result details',
    'Select entities to test coverage',
    'Add coverage scores to relationships',
  ];
  const lastStep = steps.length - 1;

  const stepDisabled = (step: number) => {
    return step >= activeStep;
  };

  return (
    <Stepper activeStep={activeStep}>
      {steps.map((label, step) => (
        <Step key={label} disabled={stepDisabled(step)}>
          <StepButton onClick={step < lastStep ? () => onStepClick(step) : undefined}>
            {t_i18n(label)}
          </StepButton>
        </Step>
      ))}
    </Stepper>
  );
};

export default SecurityCoverageResultFormSteps;
