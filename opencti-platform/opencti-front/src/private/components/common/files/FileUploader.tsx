import React, { FunctionComponent, useRef, useState } from 'react';
import { graphql } from 'react-relay';
import { CloudUploadOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { File } from 'mdi-material-ui';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { FileUploaderEntityMutation$data } from './__generated__/FileUploaderEntityMutation.graphql';
import { FileUploaderGlobalMutation$data } from './__generated__/FileUploaderGlobalMutation.graphql';
import {
  ExternalReferenceCreationMutation$data,
} from '../../analysis/external_references/__generated__/ExternalReferenceCreationMutation.graphql';
import { externalReferenceCreationMutation } from '../../analysis/external_references/ExternalReferenceCreation';
import {
  externalReferenceLinesMutationRelationAdd,
} from '../../analysis/external_references/AddExternalReferencesLines';

const fileUploaderGlobalMutation = graphql`
  mutation FileUploaderGlobalMutation($file: Upload!) {
    uploadImport(file: $file) {
      id
      ...FileLine_file
    }
  }
`;

const fileUploaderEntityMutation = graphql`
  mutation FileUploaderEntityMutation($id: ID!, $file: Upload!) {
    stixCoreObjectEdit(id: $id) {
      importPush(file: $file) {
        id
        ...FileLine_file
      }
    }
  }
`;

interface FileUploaderProps {
  entityId: string,
  onUploadSuccess: (id?: string) => unknown,
  color: 'inherit' | 'primary' | 'secondary' | 'success' | 'error' | 'info' | 'warning' | undefined,
  accept?: string,
  size: 'small' | 'large' | 'medium' | undefined,
  nameInCallback?: boolean,
  createExternalRef?: boolean,
}

const FileUploader: FunctionComponent<FileUploaderProps> = ({ entityId, onUploadSuccess, color, accept, size, nameInCallback, createExternalRef }) => {
  const { t } = useFormatter();

  const uploadRef = useRef<HTMLInputElement | null>(null);
  const [upload, setUpload] = useState<string | null>(null);

  const handleOpenUpload = () => uploadRef.current?.click();

  const handleLinkExternalRef = (ref: ExternalReferenceCreationMutation$data) => {
    commitMutation({
      mutation: externalReferenceLinesMutationRelationAdd,
      variables: {
        id: ref.externalReferenceAdd?.id,
        input: {
          fromId: entityId,
          relationship_type: 'external-reference',
        },
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('File successfully uploaded and associated external reference successfully created');
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      setSubmitting: undefined,
      onError: undefined,
    });
  };

  const handleCreateExternalRef = (file: File, fileId?: string) => {
    const externalReferenceValues = {
      source_name: file.name.length > 2 ? file.name : (t('FromFile') + file.name),
      description: t('(file uploaded in Data)'),
      file,
      fileId,
    };
    commitMutation({
      mutation: externalReferenceCreationMutation,
      variables: {
        input: externalReferenceValues,
      },
      onCompleted: (externalRefResult: ExternalReferenceCreationMutation$data) => {
        console.log('externalRefResult', externalRefResult);
        handleLinkExternalRef(externalRefResult); // link the external reference to the entity
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      setSubmitting: undefined,
      onError: undefined,
    });
  };

  const handleUpload = (file: File) => {
    commitMutation({
      mutation: entityId
        ? fileUploaderEntityMutation
        : fileUploaderGlobalMutation,
      variables: { file, id: entityId },
      optimisticUpdater: () => {
        setUpload(file.name);
      },
      onCompleted: (result: FileUploaderEntityMutation$data | FileUploaderGlobalMutation$data) => {
        if (uploadRef.current?.value) {
          uploadRef.current.value = ''; // Reset the upload input
        }
        setUpload(null);
        MESSAGING$.notifySuccess('File successfully uploaded');
        const fileId = entityId
          ? (result as FileUploaderEntityMutation$data).stixCoreObjectEdit?.importPush?.id
          : (result as FileUploaderGlobalMutation$data).uploadImport?.id;
        if (nameInCallback) {
          onUploadSuccess(fileId);
        } else {
          onUploadSuccess();
        }
        if (createExternalRef) {
          console.log('fileId', fileId);
          handleCreateExternalRef(file, fileId); // creation of the external reference associated to the file
        }
      },
      updater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return (
    <React.Fragment>
      {accept ? (
        <input
          ref={uploadRef}
          type="file"
          style={{ display: 'none' }}
          onChange={({
            target: {
              validity,
              files,
            },
          }) => {
            const file = files?.item(0);
            if (file) {
              return validity.valid && handleUpload(file);
            }
            return false;
          }
          }
          accept={accept}
        />
      ) : (
        <input
          ref={uploadRef}
          type="file"
          style={{ display: 'none' }}
          onChange={({
            target: {
              validity,
              files,
            },
          }) => {
            const file = files?.item(0);
            if (file) {
              return validity.valid && handleUpload(file);
            }
            return false;
          }
          }
        />
      )}
      {upload ? (
        <Tooltip
          title={`Uploading ${upload}`}
          aria-label={`Uploading ${upload}`}
        >
          <IconButton disabled={true} size={size || 'large'}>
            <CircularProgress
              size={24}
              thickness={2}
              color={color || 'primary'}
            />
          </IconButton>
        </Tooltip>
      ) : (
        <Tooltip title={t('Select your file')} aria-label="Select your file">
          <IconButton
            onClick={handleOpenUpload}
            aria-haspopup="true"
            color={color || 'primary'}
            size={size || 'large'}
          >
            <CloudUploadOutlined />
          </IconButton>
        </Tooltip>
      )}
    </React.Fragment>
  );
};

export default FileUploader;
