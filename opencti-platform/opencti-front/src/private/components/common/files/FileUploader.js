import React, { useRef, useState } from 'react';
import * as PropTypes from 'prop-types';
import graphql from 'babel-plugin-relay/macro';
import { CloudUploadOutlined } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import Tooltip from '@material-ui/core/Tooltip';
import CircularProgress from '@material-ui/core/CircularProgress';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const FileUploaderGlobalMutation = graphql`
  mutation FileUploaderEntityMutation($file: Upload!) {
    uploadImport(file: $file) {
      ...FileLine_file
    }
  }
`;

const FileUploaderEntityMutation = graphql`
  mutation FileUploaderGlobalMutation($id: ID!, $file: Upload!) {
    stixDomainEntityEdit(id: $id) {
      importPush(file: $file) {
        ...FileLine_file
      }
    }
  }
`;

const FileUploader = (props) => {
  const { entityId, onUploadSuccess, t } = props;
  const uploadRef = useRef(null);
  const [upload, setUpload] = useState(null);
  const handleOpenUpload = () => uploadRef.current.click();
  const handleUpload = (file) => {
    commitMutation({
      mutation: entityId
        ? FileUploaderEntityMutation
        : FileUploaderGlobalMutation,
      variables: { file, id: entityId },
      optimisticUpdater: () => {
        setUpload(file.name);
      },
      onCompleted: () => {
        uploadRef.current.value = null; // Reset the upload input
        setUpload(null);
        MESSAGING$.notifySuccess('File successfully uploaded');
        onUploadSuccess();
      },
    });
  };
  return (
    <React.Fragment>
      <input
        ref={uploadRef}
        type="file"
        style={{ display: 'none' }}
        onChange={({
          target: {
            validity,
            files: [file],
          },
        }) =>
          // eslint-disable-next-line implicit-arrow-linebreak
          validity.valid && handleUpload(file)
        }
      />
      {upload ? (
        <Tooltip
          title={`Uploading ${upload}`}
          aria-label={`Uploading ${upload}`}
        >
          <IconButton disabled={true}>
            <CircularProgress size={24} thickness={2} />
          </IconButton>
        </Tooltip>
      ) : (
        <Tooltip title={t('Select your file')} aria-label="Select your file">
          <IconButton
            onClick={handleOpenUpload}
            aria-haspopup="true"
            color="primary"
          >
            <CloudUploadOutlined />
          </IconButton>
        </Tooltip>
      )}
    </React.Fragment>
  );
};

FileUploader.propTypes = {
  entityId: PropTypes.string,
  onUploadSuccess: PropTypes.func.isRequired,
};

export default inject18n(FileUploader);
