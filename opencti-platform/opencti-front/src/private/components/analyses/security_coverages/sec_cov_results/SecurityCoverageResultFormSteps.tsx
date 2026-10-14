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
    ...(isUpdate ? [t_i18n('Select security coverage result to update')] : []),
    t_i18n('Coverage Result details'),
    t_i18n('Select entities to test coverage'),
    t_i18n('Add coverage scores to relationships'),
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
            {label}
          </StepButton>
        </Step>
      ))}
    </Stepper>
  );
};

export default SecurityCoverageResultFormSteps;
