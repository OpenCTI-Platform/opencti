import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stepper, Step, StepButton, Typography, Box } from '@mui/material';
import { Formik } from 'formik';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import ImportFilesUploader from '@components/common/files/import_files/ImportFilesUploader';
import ImportFilesOptions from '@components/common/files/import_files/ImportFilesOptions';
import { useFormatter } from '../../../../../components/i18n';
import Transition from '../../../../../components/Transition';

interface ImportFilesDialogProps {
  open: boolean;
  handleClose: () => void;
}

const ImportFilesConfigurations = () => {
  return (<Box>CONFIG</Box>);
};

type SubmittedFormValues = {
  fileMarkings: Option[];
  associatedEntity: AssociatedEntityOption;
};

const ImportFilesDialog = ({ open, handleClose }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const [activeStep, setActiveStep] = useState(0);
  const [files, setFiles] = useState<File[]>([]);

  const steps = ['Select files', 'Specific files configurations', 'Import options'];

  const onCancel = () => {
    handleClose();
    setActiveStep(0);
    setFiles([]);
  };

  const handleSubmit = (values: SubmittedFormValues) => {
    console.log({ files, values });
    handleClose();
  };

  return (
    <Formik
      enableReinitialize={true}
      initialValues={{
        fileMarkings: [],
        associatedEntity: { label: '', value: '', type: '' },
      }}
      onSubmit={handleSubmit}
    >
      {({ resetForm, submitForm, setFieldValue }) => (
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
          <DialogTitle>
            <Typography variant="h5">{t_i18n('Import files')}</Typography>
          </DialogTitle>
          <DialogContent sx={{ paddingInline: 20, marginBlock: 10 }}>
            <Stepper nonLinear activeStep={activeStep} sx={{ marginInline: 10 }}>
              {steps.map((label, index) => (
                <Step key={label}>
                  <StepButton color="inherit" onClick={() => setActiveStep(index)}>
                    {label}
                  </StepButton>
                </Step>
              ))}
            </Stepper>
            <Box sx={{ paddingBlock: 10 }}>
              {activeStep === 0 && <ImportFilesUploader files={files} onChange={(newFiles) => setFiles(newFiles)} />}
              {activeStep === 1 && <ImportFilesConfigurations />}
              {activeStep === 2 && <ImportFilesOptions setFieldValue={setFieldValue}/>}
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => {
              resetForm();
              onCancel();
            }}
            >
              {t_i18n('Cancel')}
            </Button>
            {activeStep !== steps.length - 1 ? (
              <Button onClick={() => setActiveStep(activeStep + 1)} color="secondary">
                {t_i18n('Next')}
              </Button>
            ) : (
              <Button onClick={submitForm} color="secondary">
                {t_i18n('Import')}
              </Button>
            )}
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default ImportFilesDialog;
