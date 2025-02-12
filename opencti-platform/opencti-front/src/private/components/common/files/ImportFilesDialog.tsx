import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stepper, Step, StepButton } from '@mui/material';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';

interface ImportFilesDialogProps {
  open: boolean;
  handleClose: () => void;
}

const ImportFilesDialog = ({ open, handleClose } : ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const [activeStep, setActiveStep] = useState(0);
  const [data, setData] = useState({});

  const steps = ['Select files', 'Specific files configurations', 'Import options'];

  const onCancel = () => {
    handleClose();
    setActiveStep(0);
    setData({});
  };

  const handleSubmit = () => {
    console.log('Submit:', data);
    handleClose();
  };

  return (
    <Dialog
      open={open}
      TransitionComponent={Transition}
      fullWidth
      maxWidth={false}
      PaperProps={{
        elevation: 1,
        style: {
          height: '100vh',
        },
      }}
    >
      <DialogTitle><Typography variant="h5">{t_i18n('Import files')}</Typography></DialogTitle>
      <DialogContent sx={{ padding: 20 }}>
        <Stepper nonLinear activeStep={activeStep} >
          {steps.map((label, index) => (
            <Step key={label}>
              <StepButton color="inherit" onClick={() => setActiveStep(index)}>
                {label}
              </StepButton>
            </Step>
          ))}
        </Stepper>
      </DialogContent>
      <DialogActions>
        <Button onClick={() => onCancel()}>
          {t_i18n('Cancel')}
        </Button>
        {activeStep !== steps.length - 1 ? (
          <Button onClick={() => setActiveStep(activeStep + 1)} color="secondary">
            {t_i18n('Next')}
          </Button>
        ) : (
          <Button onClick={() => handleSubmit()} color="secondary">
            {t_i18n('Submit')}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default ImportFilesDialog;
