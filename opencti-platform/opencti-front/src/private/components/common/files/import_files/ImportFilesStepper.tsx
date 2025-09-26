import { Step, StepButton, Stepper } from '@mui/material';
import React from 'react';
import { useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { useFormatter } from '../../../../../components/i18n';

const ImportFilesStepper = () => {
  const { t_i18n } = useFormatter();
  const { canSelectImportMode, activeStep, setActiveStep, files, importMode, selectedFormId } = useImportFilesContext();
  const hasSelectedFiles = files.length > 0;
  const hasSelectedForm = !!selectedFormId;

  return (
    // If canSelectImportMode is true activeStep is initialised to 1 instead of 0 (we have 2 step instead of 3)
    // we decrease 'activeStep' by 1 to adjust the stepper and skip the first step.
    <Stepper nonLinear activeStep={canSelectImportMode ? activeStep : activeStep - 1} sx={{ marginInline: 10 }}>
      {canSelectImportMode && (<Step key={'import_mode'}>
        <StepButton color="inherit" onClick={() => setActiveStep(0)}>
          {t_i18n('Import mode')}
        </StepButton>
      </Step>)}
      <Step key={'select_file_or_form'} disabled={!importMode}>
        <StepButton color="inherit" onClick={() => setActiveStep(1)}>
          {importMode === 'form' ? t_i18n('Select form') : t_i18n('Select files')}
        </StepButton>
      </Step>
      <Step key={'import_options_or_fill_form'} disabled={importMode === 'form' ? !hasSelectedForm : !hasSelectedFiles}>
        <StepButton color="inherit" onClick={() => setActiveStep(2)}>
          {importMode === 'form' ? t_i18n('Fill form') : t_i18n('Import options')}
        </StepButton>
      </Step>
    </Stepper>
  );
};

export default ImportFilesStepper;
