import React, { useCallback, useMemo, useState } from 'react';
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';
import { FormikConfig, FormikErrors, useFormik } from 'formik';
import { AssociatedEntityOption } from '@components/common/form/AssociatedEntityField';
import { Option } from '@components/common/form/ReferenceField';
import ImportFilesUploader from '@components/common/files/import_files/ImportFilesUploader';
import ImportFilesOptions from '@components/common/files/import_files/ImportFilesOptions';
import { graphql, UseMutationConfig, usePreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import ImportFilesStepper from '@components/common/files/import_files/ImportFilesStepper';
import ImportFilesUploadProgress from '@components/common/files/import_files/ImportFilesUploadProgress';
import ImportFilesToggleMode from '@components/common/files/import_files/ImportFilesToggleMode';
import { draftCreationMutation } from '@components/drafts/DraftCreation';
import { DraftCreationMutation, DraftCreationMutation$data } from '@components/drafts/__generated__/DraftCreationMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import { DraftContextBannerMutation } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import { ImportFilesProvider, importFilesQuery, useImportFilesContext } from '@components/common/files/import_files/ImportFilesContext';
import { ImportFilesContextQuery } from '@components/common/files/import_files/__generated__/ImportFilesContextQuery.graphql';
import {
  ImportFilesDialogGlobalMutation,
  ImportFilesDialogGlobalMutation$variables,
} from '@components/common/files/import_files/__generated__/ImportFilesDialogGlobalMutation.graphql';
import {
  ImportFilesDialogEntityMutation,
  ImportFilesDialogEntityMutation$variables,
} from '@components/common/files/import_files/__generated__/ImportFilesDialogEntityMutation.graphql';
import { useFormatter } from '../../../../../components/i18n';
import Transition from '../../../../../components/Transition';
import { handleErrorInForm, MESSAGING$ } from '../../../../../relay/environment';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import useBulkCommit from '../../../../../utils/hooks/useBulkCommit';
import { resolveLink } from '../../../../../utils/Entity';
import useDraftContext from '../../../../../utils/hooks/useDraftContext';
import { RelayError } from '../../../../../relay/relayTypes';
import { KNOWLEDGE_KNASKIMPORT } from '../../../../../utils/hooks/useGranted';
import Security from '../../../../../utils/Security';

export const CSV_MAPPER_NAME = '[FILE] CSV Mapper import';

const importFilesDialogGlobalMutation = graphql`
  mutation ImportFilesDialogGlobalMutation(
    $file: Upload!,
    $fileMarkings: [String!],
    $connectors: [ConnectorWithConfig!],
    $validationMode: ValidationMode,
    $draftId: String,
    $noTriggerImport: Boolean,
  ) {
    uploadAndAskJobImport(
      file: $file,
      connectors: $connectors,
      fileMarkings: $fileMarkings,
      validationMode: $validationMode
      draftId: $draftId,
      noTriggerImport: $noTriggerImport,
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
    $draftId: String,
    $noTriggerImport: Boolean,
  ) {
    stixCoreObjectEdit(id: $id) {
      uploadAndAskJobImport(
        file: $file,
        connectors: $connectors,
        fileMarkings: $fileMarkings,
        validationMode: $validationMode
        draftId: $draftId,
        noTriggerImport: $noTriggerImport,
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

interface ImportFilesDialogProps {
  open: boolean;
  handleClose: () => void;
  entityId?: string;
  draftId?: string;
}

export type OptionsFormValues = {
  fileMarkings: Option[];
  associatedEntity: AssociatedEntityOption | null;
  validationMode?: 'draft' | 'workbench';
  name: string;
};

const ImportFiles = ({ open, handleClose }: ImportFilesDialogProps) => {
  const { t_i18n } = useFormatter();

  const draftContext = useDraftContext();
  const {
    activeStep,
    setActiveStep,
    importMode,
    files,
    entityId,
    uploadStatus,
    setUploadStatus,
    draftId,
    setDraftId,
    inDraftContext,
    queryRef,
  } = useImportFilesContext();
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; status?: 'success' | 'error' }[]>([]);
  const { stixCoreObject: entity, connectorsForImport } = usePreloadedQuery<ImportFilesContextQuery>(
    importFilesQuery,
    queryRef,
  );

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

  const createDraft = useCallback(async (name: string, selectedEntityId?: string) => {
    try {
      const { draftWorkspaceAdd } = await new Promise<DraftCreationMutation$data>((resolve, reject) => {
        commitCreationMutation({
          variables: {
            input: {
              name,
              entity_id: selectedEntityId,
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

      setDraftId(draftWorkspaceAdd?.id);
      return draftWorkspaceAdd?.id;
    } catch (error) {
      const { errors } = (error as unknown as RelayError).res;
      MESSAGING$.notifyError(errors.at(0)?.message);
      return undefined;
    }
  }, [commitCreationMutation, commitContextMutation]);

  const setDraftContext = () => {
    commitContextMutation({
      variables: {
        input: [
          {
            key: 'draft_context',
            value: [draftId],
          },
        ],
      },
      onCompleted: () => {
        handleClose();
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
      },
    });
  };

  const importFiles = (
    {
      selectedEntityId,
      fileMarkingIds,
      validationMode,
      newDraftId,
    }: {
      selectedEntityId?: string,
      fileMarkingIds: string[],
      validationMode?: 'workbench' | 'draft',
      newDraftId?: string,
    },
    setErrors: (errors: FormikErrors<OptionsFormValues>) => void,
  ) => {
    const variables = files.map(({ file, connectors, configuration }) => (selectedEntityId
      ? (
        {
          id: selectedEntityId,
          file,
          connectors: importMode === 'auto' ? undefined : connectors?.map(({ id: connectorId }) => ({
            connectorId,
            configuration,
          })),
          fileMarkings: fileMarkingIds,
          validationMode,
          draftId: newDraftId,
          noTriggerImport: importMode === 'manual',
        } as ImportFilesDialogEntityMutation$variables
      ) : (
        {
          file,
          connectors: importMode === 'auto' ? undefined : connectors?.map(({ id: connectorId }) => ({
            connectorId,
            configuration,
          })),
          fileMarkings: fileMarkingIds,
          validationMode,
          draftId: newDraftId,
          noTriggerImport: importMode === 'manual',
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
    const selectedEntityId = entityId ?? (values.associatedEntity?.value || undefined);
    const fileMarkingIds = values.fileMarkings.map(({ value }) => value);

    const { validationMode, name } = values;
    if (validationMode === 'workbench') {
      setUploadStatus('uploading');
      importFiles({ selectedEntityId, fileMarkingIds, validationMode }, setErrors);
    } else if (validationMode === 'draft') {
      const newDraftId = !draftId ? await createDraft(name, selectedEntityId) : draftId;
      if (!newDraftId) {
        setActiveStep(1);
        setUploadStatus(undefined);
        throw new Error(t_i18n('Failed to create draft workspace.'));
      }
      setUploadStatus('uploading');
      importFiles({ selectedEntityId, fileMarkingIds, validationMode, newDraftId }, setErrors);
    } else {
      setUploadStatus('uploading');
      importFiles({ selectedEntityId, fileMarkingIds }, setErrors);
    }
  };

  const optionsContext = useFormik<OptionsFormValues>({
    enableReinitialize: true,
    initialValues: {
      fileMarkings: [] as Option[],
      associatedEntity: entity ? { value: entity.id, label: entity.name || entity.id, type: entity.entity_type } : null,
      validationMode: importMode === 'manual' ? 'draft' : undefined,
      name: '',
    },
    onSubmit,
  });

  // Check if a file is selected and CSV connector have a configuration mapper selected
  const isValid = useMemo(() => {
    return files.length > 0 && (importMode === 'auto' || files.every((file) => {
      const hasCsvMapperConnector = file.connectors?.some((connector) => connector.name === CSV_MAPPER_NAME);
      return hasCsvMapperConnector ? !!file.configuration : true;
    }));
  }, [files, importMode]);

  const isValidImport = useMemo(() => {
    return (optionsContext.values.validationMode === 'draft' && optionsContext.values.name.length > 0) || draftId || optionsContext.values.validationMode === 'workbench' || importMode === 'auto';
  }, [optionsContext.values, importMode]);

  const renderActions = useMemo(() => {
    if (!uploadStatus) {
      return activeStep < 2 ? (
        // Next button to move to the next step
        <Button
          onClick={() => setActiveStep(activeStep + 1)}
          color="secondary"
          disabled={!isValid}
        >
          {t_i18n('Next')}
        </Button>
      ) : (
        // Import button to submit the form
        <Button
          onClick={optionsContext.submitForm}
          color="secondary"
          disabled={!isValidImport}
        >
          {t_i18n('Import')}
        </Button>
      );
    }

    // If upload is completed successfully
    if (uploadStatus === 'success') {
      // If draft
      if (optionsContext.values.validationMode === 'draft') {
        // If already in draft do show redirect
        if (inDraftContext) return (<></>);

        return (
          // Switch to draft mode and navigate to files draft
          <Button
            color="secondary"
            onClick={() => setDraftContext()}
            component={Link}
            to={`/dashboard/drafts/${draftId}/files`}
          >
            {t_i18n('Navigate to draft')}
          </Button>
        );
      }

      // If workbench
      return (
        // Navigate to entity button (if associated entity exists)
        optionsContext.values.associatedEntity?.value ? !entityId && (
          <Button
            color="secondary"
            onClick={() => handleClose()}
            component={Link}
            to={`${resolveLink(optionsContext.values.associatedEntity.type)}/${optionsContext.values.associatedEntity.value}/files`}
          >
            {t_i18n('Navigate to entity')}
          </Button>
        )
          : (
            <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
              <Button
                color="secondary"
                onClick={() => handleClose()}
                component={Link}
                to={'/dashboard/data/import'}
              >
                {t_i18n('Navigate to import')}
              </Button>
            </Security>
          )
      );
    }

    // No actions
    return null;
  }, [
    uploadStatus,
    activeStep,
    isValid,
    isValidImport,
    optionsContext.values.validationMode,
    optionsContext.values.associatedEntity,
    draftId,
    optionsContext.submitForm,
  ]);

  return (
    <Dialog
      open={open}
      slots={{ transition: Transition }}
      fullWidth
      maxWidth={false}
      slotProps={{
        paper: {
          elevation: 1,
          style: {
            height: '100vh',
          },
        },
      }}
    >
      <DialogTitle>
        <Typography variant="h5">{t_i18n('Import files')}</Typography>
      </DialogTitle>
      <DialogContent sx={{ paddingInline: 20, marginBlock: 10 }}>
        {!uploadStatus ? (
          <>
            <ImportFilesStepper/>
            {/* Remove stepper height (25px) */}
            <Box sx={{ paddingBlock: 10, height: 'calc(100% - 25px)' }}>
              {activeStep === 0 && (<ImportFilesToggleMode/>)}
              {activeStep === 1 && (<ImportFilesUploader connectorsForImport={connectorsForImport}/>)}
              {activeStep === 2 && (
                <ImportFilesOptions optionsFormikContext={optionsContext} draftContext={draftContext}/>)}
            </Box>
          </>
        ) : (
          <ImportFilesUploadProgress
            currentCount={bulkCurrentCount}
            totalCount={bulkCount}
            uploadedFiles={uploadedFiles}
            BulkResult={BulkResult}
          />
        )}
      </DialogContent>
      <DialogActions>
        {/* Close dialog */}
        {(!uploadStatus || uploadStatus === 'success') && (
          <Button onClick={() => handleClose()}>
            {uploadStatus === 'success' ? t_i18n('Close') : t_i18n('Cancel')}
          </Button>
        )}
        {renderActions}
      </DialogActions>
    </Dialog>
  );
};

const ImportFilesDialog = ({ open, entityId, handleClose }: ImportFilesDialogProps) => {
  return (
    <ImportFilesProvider initialValue={{ entityId }}>
      <ImportFiles open={open} handleClose={handleClose}></ImportFiles>
    </ImportFilesProvider>
  );
};

export default ImportFilesDialog;
