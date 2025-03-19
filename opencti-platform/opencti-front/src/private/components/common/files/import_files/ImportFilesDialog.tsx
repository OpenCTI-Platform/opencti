import React, { useEffect, useMemo, useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography, Box } from '@mui/material';
import { FormikConfig, useFormik } from 'formik';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import ImportFilesUploader, { FileWithConnectors } from '@components/common/files/import_files/ImportFilesUploader';
import ImportFilesOptions from '@components/common/files/import_files/ImportFilesOptions';
import { graphql, UseMutationConfig, useQueryLoader } from 'react-relay';
import { ImportFilesDialogQuery } from '@components/common/files/import_files/__generated__/ImportFilesDialogQuery.graphql';
import {
  ImportFilesDialogGlobalMutation,
  ImportFilesDialogGlobalMutation$variables,
} from '@components/common/files/import_files/__generated__/ImportFilesDialogGlobalMutation.graphql';
import {
  ImportFilesDialogEntityMutation,
  ImportFilesDialogEntityMutation$variables,
} from '@components/common/files/import_files/__generated__/ImportFilesDialogEntityMutation.graphql';
import { Link } from 'react-router-dom';
import ImportFilesStepper from '@components/common/files/import_files/ImportFilesStepper';
import ImportFilesUploadProgress from '@components/common/files/import_files/ImportFilesUploadProgress';
import { useFormatter } from '../../../../../components/i18n';
import Transition from '../../../../../components/Transition';
import { handleErrorInForm } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../../utils/hooks/useBulkCommit';
import { resolveLink } from '../../../../../utils/Entity';

export const CSV_MAPPER_NAME = '[FILE] CSV Mapper import';

const importFilesDialogGlobalMutation = graphql`
  mutation ImportFilesDialogGlobalMutation(
    $file: Upload!,
    $fileMarkings: [String!],
    $connectors: [ConnectorWithConfig!],
    $validationMode: ValidationMode,
  ) {
    uploadAndAskJobImport(
      file: $file,
      connectors: $connectors,
      fileMarkings: $fileMarkings,
      validationMode: $validationMode
    ) {
      id
      ...FileLine_file
    }
  }
`;

const importFilesDialogEntityMutation = graphql`
  mutation ImportFilesDialogEntityMutation(
    $id: ID!,
    $file: Upload!,
    $fileMarkings: [String!],
    $connectors: [ConnectorWithConfig!],
    $validationMode: ValidationMode,
  ) {
    stixCoreObjectEdit(id: $id) {
      uploadAndAskJobImport(
        file: $file,
        connectors: $connectors,
        fileMarkings: $fileMarkings,
        validationMode: $validationMode
      ) {
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

export const importFilesDialogQuery = graphql`
  query ImportFilesDialogQuery {
    connectorsForImport {
      id
      name
      active
      auto
      only_contextual
      connector_scope
      updated_at
      configurations {
        id
        name
        configuration
      }
    }
  }
`;

interface ImportFilesDialogProps {
  open: boolean;
  handleClose: () => void;
  entityId?: string;
}

export type OptionsFormValues = {
  fileMarkings: Option[];
  associatedEntity: AssociatedEntityOption | null;
};

const ImportFilesDialog = ({ open, handleClose, entityId }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const [activeStep, setActiveStep] = useState(0);
  const [files, setFiles] = useState<FileWithConnectors[]>([]);
  const [uploadStatus, setUploadStatus] = useState<undefined | 'uploading' | 'success'>();
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; status?: 'success' | 'error' }[]>([]);

  const [queryRef, loadQuery] = useQueryLoader<ImportFilesDialogQuery>(importFilesDialogQuery);

  useEffect(() => {
    if (open) {
      loadQuery({});
    }
  }, [open, loadQuery]);

  const successMessage = t_i18n('Files successfully uploaded');
  const [commitGlobal] = useApiMutation<ImportFilesDialogGlobalMutation>(
    importFilesDialogGlobalMutation,
    undefined,
    { successMessage },
  );

  const [commitEntity] = useApiMutation<ImportFilesDialogEntityMutation>(
    importFilesDialogEntityMutation,
    undefined,
    { successMessage },
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

  // Check if CSV connector have a configuration mapper selected
  const isValid = useMemo(() => {
    return files.length > 0 && files.every((file) => {
      const hasCsvMapperConnector = file.connectors?.some((connector) => connector.name === CSV_MAPPER_NAME);
      return hasCsvMapperConnector ? !!file.configuration : true;
    });
  }, [files]);

  const onSubmit: FormikConfig<OptionsFormValues>['onSubmit'] = (values, { setErrors }) => {
    setUploadStatus('uploading');
    const selectedEntityId = entityId ?? (values.associatedEntity?.value || undefined);
    const fileMarkingIds = values.fileMarkings.map(({ value }) => value);

    const validationMode = 'draft';

    const variables = files.map(({ file, connectors, configuration }) => (selectedEntityId
      ? (
        {
          id: selectedEntityId,
          file,
          connectors: connectors?.map(({ id: connectorId }) => ({ connectorId, configuration })),
          fileMarkings: fileMarkingIds,
          validationMode,
        } as ImportFilesDialogEntityMutation$variables
      ) : (
        {
          file,
          connectors: connectors?.map(({ id: connectorId }) => ({ connectorId, configuration })),
          fileMarkings: fileMarkingIds,
          validationMode,
        } as ImportFilesDialogGlobalMutation$variables
      )
    ));

    setUploadedFiles(files.map(({ file: { name } }) => ({ name })));

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

  const optionsContext = useFormik<OptionsFormValues>({
    enableReinitialize: true,
    initialValues: {
      fileMarkings: [] as Option[],
      associatedEntity: null,
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
            <ImportFilesStepper activeStep={activeStep} setActiveStep={setActiveStep} hasSelectedFiles={files.length > 0} />
            <Box sx={{ paddingBlock: 10 }}>
              {activeStep === 0 && queryRef && (
                <ImportFilesUploader
                  files={files}
                  onChange={(newFiles) => setFiles(newFiles)}
                  queryRef={queryRef}
                />
              )}
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
              <Button onClick={() => setActiveStep(activeStep + 1)} color="secondary" disabled={!isValid}>
                {t_i18n('Next')}
              </Button>
            ) : (
              <Button onClick={optionsContext.submitForm} color="secondary">
                {t_i18n('Import')}
              </Button>
            )}
          </>
        ) : uploadStatus === 'success' && (
          <>
            <Button onClick={() => handleClose()}>
              {t_i18n('Close')}
            </Button>
            {optionsContext.values.associatedEntity?.value && (
              <Button
                color="secondary"
                onClick={() => handleClose()}
                component={Link}
                to={`${resolveLink(optionsContext.values.associatedEntity.type)}/${optionsContext.values.associatedEntity.value}/files`}
              >
                {t_i18n('Navigate to entity')}
              </Button>
            )}
          </>
        )
            }
      </DialogActions>
    </Dialog>
  );
};

export default ImportFilesDialog;
