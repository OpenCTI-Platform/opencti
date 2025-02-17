import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stepper, Step, StepButton, Typography, Box } from '@mui/material';
import { Formik } from 'formik';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import ImportFilesUploader from '@components/common/files/import_files/ImportFilesUploader';
import ImportFilesOptions from '@components/common/files/import_files/ImportFilesOptions';
import { graphql } from 'react-relay';
import LinearProgress from '@mui/material/LinearProgress';
import { useFormatter } from '../../../../../components/i18n';
import Transition from '../../../../../components/Transition';
import { commitMutation } from '../../../../../relay/environment';

const importFilesDialogGlobalMutation = graphql`
  mutation ImportFilesDialogGlobalMutation($file: Upload!, $fileMarkings: [String]) {
    uploadImport(file: $file, fileMarkings: $fileMarkings) {
      id
      ...FileLine_file
    }
  }
`;

const importFilesDialogEntityMutation = graphql`
  mutation ImportFilesDialogEntityMutation($id: ID!, $file: Upload!, $fileMarkings: [String]) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file, fileMarkings: $fileMarkings) {
        id
        ...FileLine_file
        metaData {
          entity {
            ... on StixObject {
              id
            }
            ... on StixDomainObject {
              ...PictureManagementViewer_entity
            }
          }
        }
      }
    }
  }
`;

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
  const [progress, setProgress] = useState(0);
  const [uploadStatus, setUploadStatus] = useState<undefined | 'uploading' | 'success'>();

  const steps = ['Select files', 'Specific files configurations', 'Import options'];

  const commitFile = ({ entityId, file, fileMarkingIds }: { entityId?: string, file: File, fileMarkingIds: string[] }) => {
    return new Promise((resolve, reject) => {
      commitMutation({
        mutation: entityId
          ? importFilesDialogEntityMutation
          : importFilesDialogGlobalMutation,
        variables: {
          file,
          fileMarkings: fileMarkingIds,
          id: entityId,
        },
        onError: (error: Error) => {
          reject(error);
        },
        onCompleted: (response: object) => {
          resolve(response);
        },
        optimisticUpdater: undefined,
        updater: undefined,
        optimisticResponse: undefined,
        setSubmitting: undefined,
      });
    });
  };

  const handleSubmit = async (values: SubmittedFormValues) => {
    setUploadStatus('uploading');
    const entityId = values.associatedEntity?.value || undefined;
    const fileMarkingIds = values.fileMarkings.map(({ value }) => value);
    const filesPromises = files.map(async (file) => {
      return commitFile({ entityId, file, fileMarkingIds }).then(
        () => setProgress((prevProgress) => prevProgress + 1),
      );
    });
    await Promise.all(filesPromises);
    setUploadStatus('success');
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
      {({ submitForm, setFieldValue }) => (
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
            {!uploadStatus ? (
              <>
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
                  {activeStep === 0 && <ImportFilesUploader files={files} onChange={(newFiles) => setFiles(newFiles)}/>}
                  {activeStep === 1 && <ImportFilesConfigurations/>}
                  {activeStep === 2 && <ImportFilesOptions setFieldValue={setFieldValue}/>}
                </Box>
              </>
            ) : (
              <Box sx={{ width: '100%' }}>
                <LinearProgress variant="determinate" sx={{ flex: 1 }} value={(progress / files.length) * 100}/>
                {progress && (<Typography style={{ flexShrink: 0 }}>{`${progress} / ${files.length}`}</Typography>)}
              </Box>
            )
            }
          </DialogContent>
          <DialogActions>
            { !uploadStatus ? (
              <>
                <Button onClick={() => handleClose()}>
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
              </>
            ) : uploadStatus === 'success' && (
              <Button onClick={() => handleClose()}>
                {t_i18n('Close')}
              </Button>
            )
            }
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default ImportFilesDialog;
