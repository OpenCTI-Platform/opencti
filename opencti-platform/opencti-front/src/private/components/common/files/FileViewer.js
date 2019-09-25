import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import IconButton from '@material-ui/core/IconButton';
import { Delete, GetApp } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

const FileViewerDeleteMutation = graphql`
    mutation FileViewerDeleteMutation($fileName: String) {
        deleteFile(fileName: $fileName)
    }
`;

const FileViewerComponent = ({ entityId, files }) => {
  const handleRemove = (name, category) => {
    commitMutation({
      mutation: FileViewerDeleteMutation,
      variables: { fileName: name },
      updater: (store) => {
        const rootStore = store.getRoot();
        const conn = ConnectionHandler.getConnection(
          rootStore,
          'Pagination_files',
          { category, entityId },
        );
        ConnectionHandler.deleteNode(conn, name);
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('File successfully removed');
      },
    });
  };
  return <React.Fragment>
      {files.length ? files.map((value, index) => <div style={{ marginLeft: -15 }} key={index}>
          <IconButton onClick={() => handleRemove(value.id, value.metaData.category)} color="primary">
              <Delete />
          </IconButton>
            {/* eslint-disable-next-line react/jsx-no-target-blank */}
            <a href={`/storage/view/${value.id}`} target="_blank">{value.name}</a>
            &nbsp;&nbsp;<span style={{ fontSize: 10 }}>
            ({value.metaData.uploadtype} - {value.metaData.mimetype})
          </span>
          <IconButton href={`/storage/get/${value.id}`} aria-haspopup="true" color="primary">
            <GetApp />
          </IconButton>
      </div>) : <div style={{ padding: 10 }}>No file</div>}
  </React.Fragment>;
};

FileViewerComponent.propTypes = {
  entityId: PropTypes.string,
  files: PropTypes.array,
};

const FileViewer = createFragmentContainer(FileViewerComponent, {
  files: graphql`
        fragment FileViewer_files on File @relay(plural: true) {
           id
           name
           metaData {
             uploadtype
             category
             mimetype
           }
        }
    `,
});

export default FileViewer;
