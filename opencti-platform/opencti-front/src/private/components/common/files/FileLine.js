import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import IconButton from '@material-ui/core/IconButton';
import {
  Delete, GetApp, Warning, SlowMotionVideo,
} from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import React from 'react';
import { ConnectionHandler } from 'relay-runtime';
import * as PropTypes from 'prop-types';
import Tooltip from '@material-ui/core/Tooltip';
import Badge from '@material-ui/core/Badge';
import { filter } from 'ramda';
import moment from 'moment';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import FileJob from './FileJob';

const FileLineDeleteMutation = graphql`
    mutation FileLineDeleteMutation($fileName: String) {
        deleteImport(fileName: $fileName)
    }
`;

const FileLineAskDeleteMutation = graphql`
    mutation FileLineAskDeleteMutation($workId: ID!) {
        resetJob(id: $workId)
    }
`;

const FileLineImportAskJobMutation = graphql`
    mutation FileLineImportAskJobMutation($fileName: ID!) {
        askJobImport(fileName: $fileName) {
            ...FileLine_file
        }
    }
`;

const FileLineComponent = (props) => {
  const { file, connectors } = props;
  const { information, lastModifiedSinceMin, uploadStatus } = file;
  const isFail = uploadStatus === 'error';
  const isProgress = uploadStatus === 'progress';
  const isOutdated = isProgress && lastModifiedSinceMin > 5;
  const isImportActive = () => connectors && filter(x => x.data.active, connectors).length > 0;
  const executeRemove = (mutation, variables) => {
    commitMutation({
      mutation,
      variables,
      optimisticUpdater: (store) => {
        const fileStore = store.get(file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('progress', 'uploadStatus');
      },
      updater: (store) => {
        const fileStore = store.get(file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('progress', 'uploadStatus');
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
  const handleRemoveJob = (id, category) => {
    executeRemove(FileLineAskDeleteMutation,
      { workId: id }, id, category);
  };
  const askForImportJob = () => {
    commitMutation({
      mutation: FileLineImportAskJobMutation,
      variables: { fileName: file.id },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  };
  return <div>
    {isFail || isOutdated
      ? <IconButton color="secondary"
                    onClick={() => handleRemoveJob(file.id, file.metaData.category)}>
            <Delete/>
        </IconButton>
      : <IconButton disabled={isProgress} color="primary"
                    onClick={() => handleRemoveFile(file.id, file.metaData.category)}>
            <Delete/>
        </IconButton>
    }
    {isProgress
      ? <span>{file.name}</span>
      : <span>{moment(file.lastModified).format('ll')} - <a href={`/storage/view/${file.id}`} target="_blank" rel='noopener noreferrer'>{file.name}</a></span>}
    {(() => {
      if (isFail || isOutdated) {
        const message = isOutdated ? 'Processing timeout' : information;
        return <Tooltip title={message} aria-label={message}>
            <IconButton aria-haspopup="true" color="secondary">
                <Warning/>
            </IconButton>
        </Tooltip>;
      } if (isProgress) {
        return <IconButton aria-haspopup="true" color="primary">
            <CircularProgress size={24} thickness={2} />
        </IconButton>;
      }
      return <React.Fragment>
          <IconButton href={`/storage/get/${file.id}`} aria-haspopup="true" color="primary">
              <GetApp/>
          </IconButton>
          {
              connectors
              && <IconButton onClick={askForImportJob} disabled={!isImportActive()}
                             aria-haspopup="true">
                  <Badge color={isImportActive() ? 'primary' : 'secondary'} badgeContent={connectors.length}
                         anchorOrigin={{ horizontal: 'right', vertical: 'top' }}>
                    <SlowMotionVideo/>
                  </Badge>
              </IconButton>
          }
      </React.Fragment>;
    })()}
    <div style={{ paddingLeft: 50 }}>
        <FileJob file={file}/>
    </div>
  </div>;
};

const FileLine = createFragmentContainer(FileLineComponent, {
  file: graphql`
        fragment FileLine_file on File {
            id
            name
            information
            uploadStatus
            lastModified
            lastModifiedSinceMin
            metaData {
                category
                mimetype
            }
            ...FileJob_file
        }
    `,
});
FileLine.propTypes = {
  file: PropTypes.object.isRequired,
  connectors: PropTypes.array,
};

export default FileLine;
