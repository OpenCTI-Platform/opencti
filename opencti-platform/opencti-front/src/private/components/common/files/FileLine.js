import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import IconButton from '@material-ui/core/IconButton';
import { Delete, GetApp, Warning } from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import React from 'react';
import { ConnectionHandler } from 'relay-runtime';
import * as PropTypes from 'prop-types';
import Tooltip from '@material-ui/core/Tooltip';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';

const FileLineDeleteMutation = graphql`
    mutation FileLineDeleteMutation($fileName: String) {
        deleteImport(fileName: $fileName)
    }
`;

const FileLineAskDeleteMutation = graphql`
    mutation FileLineAskDeleteMutation($exportId: ID!) {
        resetExport(exportId: $exportId)
    }
`;

const FileLineComponent = (props) => {
  const { file, entityId } = props;
  const { lastModifiedSinceMin } = file;
  const isProgress = file.uploadStatus === 'inProgress';
  const isOutdatedAsk = isProgress && lastModifiedSinceMin > 5;
  const executeRemove = (mutation, variables, name, category) => {
    commitMutation({
      mutation,
      variables,
      optimisticUpdater: (store) => {
        const fileStore = store.get(file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('inProgress', 'uploadStatus');
      },
      updater: (store) => {
        const fileStore = store.get(file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('inProgress', 'uploadStatus');
        if (category === 'import') { // If export, just wait for the refresh
          const entity = store.get(entityId);
          const conn = ConnectionHandler.getConnection(entity, `Pagination_${category}Files`);
          ConnectionHandler.deleteNode(conn, name);
        }
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('File successfully removed');
      },
    });
  };
  const handleRemoveFile = (name, category) => {
    executeRemove(FileLineDeleteMutation,
      { fileName: name }, name, category);
  };
  const handleRemoveAsk = (name, category) => {
    executeRemove(FileLineAskDeleteMutation,
      { exportId: name }, name, category);
  };
  return <div>
    {isOutdatedAsk
      ? <IconButton color="secondary"
                    onClick={() => handleRemoveAsk(file.id, file.metaData.category)}>
            <Delete/>
        </IconButton>
      : <IconButton disabled={isProgress} color="primary"
                    onClick={() => handleRemoveFile(file.id, file.metaData.category)}>
            <Delete/>
        </IconButton>
    }

    {isProgress
      ? <span>{file.name}</span>
      : <a href={`/storage/view/${file.id}`} target="_blank" rel='noopener noreferrer'>{file.name}</a>}

    {(() => {
      if (isOutdatedAsk) {
        return <Tooltip title="Technical failure" aria-label="Technical failure">
            <IconButton aria-haspopup="true" color="secondary">
                <Warning/>
            </IconButton>
        </Tooltip>;
      } if (isProgress) {
        return <IconButton aria-haspopup="true" color="primary">
            <CircularProgress size={24} thickness={2} />
        </IconButton>;
      }
      return <IconButton href={`/storage/get/${file.id}`} aria-haspopup="true" color="primary">
          <GetApp/>
      </IconButton>;
    })()}
  </div>;
};

const FileLine = createFragmentContainer(FileLineComponent, {
  file: graphql`
        fragment FileLine_file on File {
            id
            name
            uploadStatus
            lastModifiedSinceMin
            metaData {
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
