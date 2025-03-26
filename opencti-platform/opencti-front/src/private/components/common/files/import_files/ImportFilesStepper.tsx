import { Step, StepButton, Stepper } from '@mui/material';
import React from 'react';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { useFormatter } from '../../../../../components/i18n';

const ImportFilesStepper = () => {
  const { t_i18n } = useFormatter();
  const { canSelectImportMode, activeStep, setActiveStep, files } = useImportFilesContext();
  const hasSelectedFiles = files.length > 0;

  return (
    <Stepper nonLinear activeStep={activeStep} sx={{ marginInline: 10 }}>
      {canSelectImportMode && (<Step key={'import_mode'}>
        <StepButton color="inherit" onClick={() => setActiveStep(0)}>
          {t_i18n('Import mode')}
        </StepButton>
      </Step>)}
      <Step key={'select_file'}>
        <StepButton color="inherit" onClick={() => setActiveStep(1)}>
          {t_i18n('Select files')}
        </StepButton>
      </Step>
      <Step key={'import_options'} disabled={!hasSelectedFiles}>
        <StepButton color="inherit" onClick={() => setActiveStep(2)}>
          { t_i18n('Import options') }
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default ImportFilesStepper;
