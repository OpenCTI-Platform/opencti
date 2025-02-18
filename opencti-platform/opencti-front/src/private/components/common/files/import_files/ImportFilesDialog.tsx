import React, { useEffect, useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Stepper, Step, StepButton, Typography, Box, ListItem, List } from '@mui/material';
import { Formik } from 'formik';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import ImportFilesUploader from '@components/common/files/import_files/ImportFilesUploader';
import ImportFilesOptions from '@components/common/files/import_files/ImportFilesOptions';
import { graphql } from 'react-relay';
import LinearProgress from '@mui/material/LinearProgress';
import { ImportFilesDialogGlobalMutation } from '@components/common/files/import_files/__generated__/ImportFilesDialogGlobalMutation.graphql';
import { ImportFilesDialogEntityMutation } from '@components/common/files/import_files/__generated__/ImportFilesDialogEntityMutation.graphql';
import { CancelOutlined, CheckCircleOutlined, UploadFileOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../../../components/i18n';
import Transition from '../../../../../components/Transition';
import { handleErrorInForm } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../../utils/hooks/useBulkCommit';
import { resolveLink } from '../../../../../utils/Entity';

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

type SubmittedFormValues = {
  fileMarkings: Option[];
  associatedEntity: AssociatedEntityOption;
};

const ImportFilesDialog = ({ open, handleClose }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const [activeStep, setActiveStep] = useState(0);
  const [files, setFiles] = useState<File[]>([]);
  const [uploadStatus, setUploadStatus] = useState<undefined | 'uploading' | 'success'>();
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; status?: 'success' | 'error' }[]>([]);

  const steps = ['Select files', 'Import options'];

  const [commitGlobal] = useApiMutation<ImportFilesDialogGlobalMutation>(
    importFilesDialogGlobalMutation,
    undefined,
    { successMessage: `${t_i18n('files')} ${t_i18n('successfully uploaded')}` },
  );

  const [commitEntity] = useApiMutation<ImportFilesDialogEntityMutation>(
    importFilesDialogEntityMutation,
    undefined,
    { successMessage: `${t_i18n('files')} ${t_i18n('successfully uploaded')}` },
  );

  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
  } = useBulkCommit<ImportFilesDialogGlobalMutation | ImportFilesDialogEntityMutation>({
    commit: commitGlobal,
    type: 'files',
  });

  const handleSubmit = (values: SubmittedFormValues, { setErrors }) => {
    setUploadStatus('uploading');
    console.log({ values });
    const entityId = values.associatedEntity?.value || undefined;
    const fileMarkingIds = values.fileMarkings.map(({ value }) => value);

    const commit = entityId ? commitEntity : commitGlobal;

    const variables = files.map((file) => (entityId
      ? { id: entityId, file, fileMarkings: fileMarkingIds }
      : { file, fileMarkings: fileMarkingIds }));
    setUploadedFiles(files.map(({ name }) => ({ name })));

    bulkCommit({
      commit,
      variables,
      onStepError: (error, { file: { name } }) => {
        handleErrorInForm(error, setErrors);
        setUploadedFiles((prevUploadedFiles) => {
          return prevUploadedFiles.map((prevFile) => {
            return prevFile.name === name ? { name, status: 'error' } : prevFile;
          });
        });
        setUploadStatus('success');
      },
      onStepCompleted: ({ file: { name } }) => {
        setUploadedFiles((prevUploadedFiles) => {
          return prevUploadedFiles.map((prevFile, i) => {
            return prevFile.name === name ? { name, status: 'success' } : prevFile;
          });
        });
      },
      onCompleted: () => {
        setUploadStatus('success');
      },
    });
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
      {({ submitForm, setFieldValue, values }) => (
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
                  {activeStep === 1 && <ImportFilesOptions setFieldValue={setFieldValue}/>}
                </Box>
              </>
            ) : (
              <div style={{ display: 'flex', height: '100%', justifyContent: 'center', flexDirection: 'column' }}>
                <Box sx={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  <LinearProgress
                    variant="buffer"
                    sx={{ flex: 1 }}
                    value={(bulkCurrentCount / bulkCount) * 100}
                    valueBuffer={((bulkCurrentCount / bulkCount) * 100) + 10}
                  />
                  <Typography style={{ flexShrink: 0 }}>{`${bulkCurrentCount}/${bulkCount}`}</Typography>
                </Box>
                <List>
                  {uploadedFiles.map((file) => (
                    <ListItem
                      divider
                      secondaryAction={
                        file.status === 'error' ? (
                          <CancelOutlined fontSize="small" color="error"/>
                        ) : (
                          <CheckCircleOutlined fontSize="small" color={file.status ?? 'inherit'}/>
                        )
                      }
                    >
                      <UploadFileOutlined color="primary" sx={{ marginRight: 2 }} />
                      {file.name}
                    </ListItem>
                  ))}
                </List>
                {uploadStatus === 'success' && (
                  <BulkResult variablesToString={(v) => v} />
                )}
              </div>
            )
            }
          </DialogContent>
          <DialogActions>
            {!uploadStatus ? (
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
            ) : uploadStatus === 'success'
              && (
                (values.associatedEntity?.value || undefined) ? (<Button onClick={() => handleClose()} component={Link} to={`${resolveLink(values.associatedEntity.type)}/${values.associatedEntity.value}/files`}>
                  {t_i18n('Navigate to entity')}
                </Button>)
                  : (<Button onClick={() => handleClose()}>
                    {t_i18n('Close')}
                  </Button>)
              )
            }
          </DialogActions>
        </Dialog>
      )}
    </Formik>
  );
};

export default ImportFilesDialog;
