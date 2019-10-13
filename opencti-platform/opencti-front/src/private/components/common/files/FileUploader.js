import React, { useRef, useState } from 'react';
import * as PropTypes from 'prop-types';
import { includes, map } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { CloudUpload } from '@material-ui/icons';
import IconButton from '@material-ui/core/IconButton';
import { ConnectionHandler } from 'relay-runtime';
import Tooltip from '@material-ui/core/Tooltip';
import CircularProgress from '@material-ui/core/CircularProgress';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

const FileUploaderMutation = graphql`
  mutation FileUploaderMutation($input: FileUpload) {
    uploadImport(input: $input) {
      ...FileLine_file
    }
  }
`;

const FileUploader = (props) => {
  const { entityId } = props;
  const uploadRef = useRef(null);
  const [upload, setUpload] = useState(null);
  const handleOpenUpload = () => uploadRef.current.click();
  const handleUpload = (file) => {
    commitMutation({
      mutation: FileUploaderMutation,
      variables: { input: { file, entityId } },
      optimisticUpdater: () => {
        setUpload(file.name);
      },
      updater: (store) => {
        const payload = store.getRootField('uploadImport');
        const newEdge = payload.setLinkedRecord(payload, 'node');
        const entity = store.get(entityId);
        const conn = ConnectionHandler.getConnection(entity, 'Pagination_importFiles');
        // Insert element only if not exists in the current listing
        const fileId = payload.getDataID();
        const edges = conn.getLinkedRecords('edges');
        const ids = map(r => r.getLinkedRecord('node').getValue('id'), edges);
        if (!includes(fileId, ids)) {
          ConnectionHandler.insertEdgeBefore(conn, newEdge);
        }
      },
      onCompleted: () => {
        uploadRef.current.value = null; // Reset the upload input
        setUpload(null);
        MESSAGING$.notifySuccess('File successfully uploaded');
      },
    });
  };
  return <React.Fragment>
    <input ref={uploadRef} type="file" style={{ display: 'none' }}
      onChange={({ target: { validity, files: [file] } }) =>
        // eslint-disable-next-line implicit-arrow-linebreak
        validity.valid && handleUpload(file)
    }/>
    { upload ? <Tooltip title={`Uploading ${upload}`} aria-label={`Uploading ${upload}`}>
          <IconButton disabled={true}>
            <CircularProgress size={24} thickness={2} />
          </IconButton>
        </Tooltip>
      : <Tooltip title="Select your file" aria-label="Select your file">
      <IconButton onClick={handleOpenUpload} aria-haspopup="true" color="primary">
        <CloudUpload/>
      </IconButton>
    </Tooltip>}
</React.Fragment>;
};

FileUploader.propTypes = {
  entityId: PropTypes.string,
};

export default FileUploader;
