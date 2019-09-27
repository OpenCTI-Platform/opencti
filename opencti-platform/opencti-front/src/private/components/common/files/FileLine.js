import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import IconButton from '@material-ui/core/IconButton';
import { Delete, GetApp } from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import React from 'react';
import { ConnectionHandler } from 'relay-runtime';
import * as PropTypes from 'prop-types';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

const FileLineDeleteMutation = graphql`
    mutation FileLineDeleteMutation($fileName: String) {
        deleteFile(fileName: $fileName)
    }
`;

const FileLineComponent = (props) => {
  const { file, entityId } = props;
  const handleRemove = (name, category) => {
    commitMutation({
      mutation: FileLineDeleteMutation,
      variables: { fileName: name },
      updater: (store) => {
        const entity = store.get(entityId);
        const conn = ConnectionHandler.getConnection(entity, `Pagination_${category}Files`);
        ConnectionHandler.deleteNode(conn, name);
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('File successfully removed');
      },
    });
  };
  return <div>
    <IconButton disabled={file.uploadStatus === 'inProgress'}
                onClick={() => handleRemove(file.id, file.metaData.category)} color="primary">
        <Delete />
    </IconButton>
    {/* eslint-disable-next-line react/jsx-no-target-blank */}
    <a href={`/storage/view/${file.id}`} target="_blank">{file.name}</a>
    &nbsp;&nbsp;<span style={{ fontSize: 10 }}>({file.metaData.uploadtype})</span>
    {file.uploadStatus === 'inProgress'
      ? <IconButton aria-haspopup="true" color="primary">
            <CircularProgress size={24} thickness={2} />
        </IconButton>
      : <IconButton href={`/storage/get/${file.id}`} aria-haspopup="true" color="primary">
            <GetApp/>
        </IconButton>
    }
</div>;
};

const FileLine = createFragmentContainer(FileLineComponent, {
  file: graphql`
        fragment FileLine_file on File {
            id
            name
            uploadStatus
            metaData {
                uploadtype
                category
                mimetype
            }
        }
    `,
});
FileLine.propTypes = {
  entityId: PropTypes.string.isRequired,
  file: PropTypes.object.isRequired,
};

export default FileLine;
