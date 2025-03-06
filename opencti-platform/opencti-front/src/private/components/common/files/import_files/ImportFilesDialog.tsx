import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography, Box } from '@mui/material';
import { FormikConfig, FormikErrors, useFormik } from 'formik';
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
import { draftCreationMutation } from '@components/drafts/DraftCreation';
import { DraftCreationMutation, DraftCreationMutation$data } from '@components/drafts/__generated__/DraftCreationMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import { DraftContextBannerMutation, DraftContextBannerMutation$data } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import { useFormatter } from '../../../../../components/i18n';
import Transition from '../../../../../components/Transition';
import { handleErrorInForm } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../../utils/hooks/useBulkCommit';
import { resolveLink } from '../../../../../utils/Entity';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';

export const CSV_MAPPER_NAME = '[FILE] CSV Mapper import';

const importFilesDialogGlobalMutation = graphql`
  mutation ImportFilesDialogGlobalMutation(
    $file: Upload!,
    $fileMarkings: [String],
    $connectors: [ConnectorWithConfig],
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
    $fileMarkings: [String],
    $connectors: [ConnectorWithConfig],
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
  associatedEntity: AssociatedEntityOption;
  validationMode: 'draft' | 'workbench';
  draftName: string;
};

const ImportFilesDialog = ({ open, handleClose, entityId }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const draftContext = useDraftContext();
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

  const [commitCreationMutation] = useApiMutation<DraftCreationMutation>(draftCreationMutation, undefined, {
    errorMessage: t_i18n('Failed to create draft workspace.'),
    successMessage: t_i18n('Draft workspace created successfully.'),
  });

  const [commitContextMutation] = useApiMutation<DraftContextBannerMutation>(draftContextBannerMutation, undefined, {
    errorMessage: t_i18n('Failed to set draft context.'),
    successMessage: t_i18n('Draft context set successfully.'),
  });
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

  // Check if a file is selected and CSV connector have a configuration mapper selected
  const isValid = useMemo(() => {
    return files.length > 0 && files.every((file) => {
      const hasCsvMapperConnector = file.connectors?.some((connector) => connector.name === CSV_MAPPER_NAME);
      return hasCsvMapperConnector ? !!file.configuration : true;
    });
  }, [files]);

  const handleCreateDraftAndSetContext = useCallback(async (name: string) => {
    // Create the draft workspace
    const { draftWorkspaceAdd } = await new Promise<DraftCreationMutation$data>((resolve, reject) => {
      commitCreationMutation({
        variables: {
          input: {
            name,
          },
        },
        onCompleted: (response, errors) => {
          if (errors) {
            reject(errors);
          } else {
            resolve(response);
          }
        },
        onError: (error) => {
          reject(error);
        },
      });
    });
    const draftId = draftWorkspaceAdd?.id;

    // Set the draft context
    return new Promise<DraftContextBannerMutation$data>((resolve, reject) => {
      commitContextMutation({
        variables: {
          input: [
            {
              key: 'draft_context',
              value: [draftId],
            },
          ],
        },
        onCompleted: (response, errors) => {
          if (errors) {
            reject(errors);
          } else {
            resolve(response);
          }
        },
        onError: (error) => {
          reject(error);
        },
      });
    });
  }, [commitCreationMutation, commitContextMutation]);

  const importFiles = (
    selectedEntityId: string | undefined,
    fileMarkingIds: string[],
    validationMode: 'workbench' | 'draft',
    setErrors: (errors: FormikErrors<OptionsFormValues>) => void,
  ) => {
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

  const onSubmit: FormikConfig<OptionsFormValues>['onSubmit'] = async (values, { setErrors }) => {
    setUploadStatus('uploading');
    const selectedEntityId = entityId ?? (values.associatedEntity?.value || undefined);
    const fileMarkingIds = values.fileMarkings.map(({ value }) => value);

    const { validationMode, draftName } = values;
    if (validationMode === 'draft') {
      await handleCreateDraftAndSetContext(draftName);

      importFiles(selectedEntityId, fileMarkingIds, validationMode, setErrors);
    }
  };

  const optionsContext = useFormik({
    enableReinitialize: true,
    initialValues: {
      fileMarkings: [] as Option[],
      associatedEntity: { label: '', value: '', type: '' } as AssociatedEntityOption,
      validationMode: draftContext || files.length > 1 ? 'draft' : 'workbench',
      draftName: '',
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
              {activeStep === 1 && (
                <ImportFilesOptions
                  optionsFormikContext={optionsContext}
                  entityId={entityId}
                  draftContext={draftContext}
                  isWorkbenchEnabled={files.length === 1}
                />
              )}
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
