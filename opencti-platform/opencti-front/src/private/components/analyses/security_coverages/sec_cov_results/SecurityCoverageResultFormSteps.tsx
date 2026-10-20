import { Box, Step, StepButton, Stepper } from '@mui/material';
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
    ...(isUpdate ? [t_i18n('Select result')] : []),
    t_i18n('Result details'),
    t_i18n('Select entities to test'),
    t_i18n('Coverage scores'),
  ];
  const lastStep = steps.length - 1;

  const stepDisabled = (step: number) => {
    return step >= activeStep;
  };

  return (
    <Box sx={{ marginBottom: 2.5 }}>
      <Stepper activeStep={activeStep}>
        {steps.map((label, step) => (
          <Step key={label} disabled={stepDisabled(step)}>
            <StepButton onClick={step < lastStep ? () => onStepClick(step) : undefined}>
              {label}
            </StepButton>
          </Step>
        ))}
      </Stepper>
    </Box>
  );
};

export default SecurityCoverageResultFormSteps;
