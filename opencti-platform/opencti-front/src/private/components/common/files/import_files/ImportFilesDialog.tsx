import React, { useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography, Box } from '@mui/material';
import { FormikConfig, useFormik } from 'formik';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import ImportFilesUploader from '@components/common/files/import_files/ImportFilesUploader';
import ImportFilesOptions from '@components/common/files/import_files/ImportFilesOptions';
import { graphql, UseMutationConfig } from 'react-relay';
import { ImportFilesDialogGlobalMutation } from '@components/common/files/import_files/__generated__/ImportFilesDialogGlobalMutation.graphql';
import { ImportFilesDialogEntityMutation } from '@components/common/files/import_files/__generated__/ImportFilesDialogEntityMutation.graphql';
import { Link } from 'react-router-dom';
import ImportFilesStepper from '@components/common/files/import_files/ImportFilesStepper';
import ImportFilesUploadProgress from '@components/common/files/import_files/ImportFilesUploadProgress';
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
  entityId?: string;
}

type OptionsFormValues = {
  fileMarkings: Option[];
  associatedEntity: AssociatedEntityOption;
};

const ImportFilesDialog = ({ open, handleClose, entityId }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const [activeStep, setActiveStep] = useState(0);
  const [files, setFiles] = useState<File[]>([]);
  const [uploadStatus, setUploadStatus] = useState<undefined | 'uploading' | 'success'>();
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; status?: 'success' | 'error' }[]>([]);

  const [commitGlobal] = useApiMutation<ImportFilesDialogGlobalMutation>(
    importFilesDialogGlobalMutation,
    undefined,
    { successMessage: t_i18n('files successfully uploaded') },
  );

  const [commitEntity] = useApiMutation<ImportFilesDialogEntityMutation>(
    importFilesDialogEntityMutation,
    undefined,
    { successMessage: t_i18n('files successfully uploaded') },
  );

  const {
    bulkCommit,
    bulkCount,
    bulkCurrentCount,
    BulkResult,
  } = useBulkCommit<ImportFilesDialogGlobalMutation | ImportFilesDialogEntityMutation>({
    commit: (args) => (
      entityId
        ? commitEntity(args as UseMutationConfig<ImportFilesDialogEntityMutation>)
        : commitGlobal(args as UseMutationConfig<ImportFilesDialogGlobalMutation>)
    ),
    type: 'files',
  });

  const onSubmit: FormikConfig<OptionsFormValues>['onSubmit'] = (values, { setErrors }) => {
    setUploadStatus('uploading');
    const selectedEntityId = entityId ?? (values.associatedEntity?.value || undefined);
    const fileMarkingIds = values.fileMarkings.map(({ value }) => value);

    const variables = files.map((file) => (selectedEntityId
      ? { id: selectedEntityId, file, fileMarkings: fileMarkingIds }
      : { file, fileMarkings: fileMarkingIds }));

    setUploadedFiles(files.map(({ name }) => ({ name })));

    bulkCommit({
      commit: (args) => (
        selectedEntityId
          ? commitEntity(args as UseMutationConfig<ImportFilesDialogEntityMutation>)
          : commitGlobal(args as UseMutationConfig<ImportFilesDialogGlobalMutation>)
      ),
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
          return prevUploadedFiles.map((prevFile) => {
            return prevFile.name === name ? { name, status: 'success' } : prevFile;
          });
        });
      },
      onCompleted: () => {
        setUploadStatus('success');
      },
    });
  };

  const optionsContext = useFormik({
    enableReinitialize: true,
    initialValues: {
      fileMarkings: [] as Option[],
      associatedEntity: { label: '', value: '', type: '' } as AssociatedEntityOption,
    },
    onSubmit,
  });

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
      <DialogTitle>
        <Typography variant="h5">{t_i18n('Import files')}</Typography>
      </DialogTitle>
      <DialogContent sx={{ paddingInline: 20, marginBlock: 10 }}>
        {!uploadStatus ? (
          <>
            <ImportFilesStepper activeStep={activeStep} setActiveStep={setActiveStep} />
            <Box sx={{ paddingBlock: 10 }}>
              {activeStep === 0 && <ImportFilesUploader files={files} onChange={(newFiles) => setFiles(newFiles)}/>}
              {activeStep === 1 && <ImportFilesOptions optionsFormikContext={optionsContext} entityId={entityId} />}
            </Box>
          </>
        ) : (
          <ImportFilesUploadProgress
            currentCount={bulkCurrentCount}
            totalCount={bulkCount}
            uploadedFiles={uploadedFiles}
            uploadStatus={uploadStatus}
            BulkResult={BulkResult}
          />
        )}
      </DialogContent>
      <DialogActions>
        {!uploadStatus ? (
          <>
            <Button onClick={() => handleClose()}>
              {t_i18n('Cancel')}
            </Button>
            {activeStep < 1 ? (
              <Button onClick={() => setActiveStep(activeStep + 1)} color="secondary">
                {t_i18n('Next')}
              </Button>
            ) : (
              <Button onClick={optionsContext.submitForm} color="secondary">
                {t_i18n('Import')}
              </Button>
            )}
          </>
        ) : uploadStatus === 'success'
              && (
                (optionsContext.values.associatedEntity?.value || undefined) ? (
                  <Button
                    onClick={() => handleClose()}
                    component={Link}
                    to={`${resolveLink(optionsContext.values.associatedEntity.type)}/${optionsContext.values.associatedEntity.value}/files`}
                  >
                    {t_i18n('Navigate to entity')}
                  </Button>)
                  : (<Button onClick={() => handleClose()}>
                    {t_i18n('Close')}
                  </Button>)
              )
            }
      </DialogActions>
    </Dialog>
  );
};

export default ImportFilesDialog;
