import { Step, StepButton, Stepper } from '@mui/material';
import { useFormatter } from '../../../../../components/i18n';

interface SecurityCoverageResultFormStepsProps {
  activeStep: number;
}

const SecurityCoverageResultFormSteps = ({
  activeStep,
}: SecurityCoverageResultFormStepsProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Stepper activeStep={activeStep}>
      <Step disabled={true}>
        <StepButton>
          {t_i18n('Coverage details')}
        </StepButton>
      </Step>
      <Step disabled={true}>
        <StepButton>
          {t_i18n('Select entities to test coverage')}
        </StepButton>
      </Step>
      <Step disabled={true}>
        <StepButton>
          {t_i18n('Add coverage scores to relationships')}
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default SecurityCoverageResultFormSteps;
