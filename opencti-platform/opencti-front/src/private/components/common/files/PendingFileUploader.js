import React, { useRef, useState } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import { CloudUploadOutlined } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import CircularProgress from '@mui/material/CircularProgress';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';

const pendingFileUploaderMutation = graphql`
  mutation PendingFileUploaderMutation($file: Upload!, $entityId: String) {
    uploadPending(file: $file, entityId: $entityId) {
      ...FileLine_file
    }
  }
`;

const PendingFileUploader = (props) => {
  const { entityId, onUploadSuccess, t, color } = props;
  const uploadRef = useRef(null);
  const [upload, setUpload] = useState(null);
  const handleOpenUpload = () => uploadRef.current.click();
  const handleUpload = (file) => {
    commitMutation({
      mutation: pendingFileUploaderMutation,
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
        accept=".json,.stix,.stix2"
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
          <IconButton disabled={true} size="large">
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
            size="large"
          >
            <CloudUploadOutlined />
          </IconButton>
        </Tooltip>
      )}
    </React.Fragment>
  );
};

PendingFileUploader.propTypes = {
  entityId: PropTypes.string,
  onUploadSuccess: PropTypes.func.isRequired,
  color: PropTypes.string,
};

export default inject18n(PendingFileUploader);
