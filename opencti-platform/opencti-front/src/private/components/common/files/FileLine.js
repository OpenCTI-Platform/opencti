import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import moment from 'moment';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { FileOutline } from 'mdi-material-ui';
import {
  Delete,
  GetApp,
  Warning,
  SlowMotionVideo,
  Domain,
} from '@material-ui/icons';
import CircularProgress from '@material-ui/core/CircularProgress';
import Tooltip from '@material-ui/core/Tooltip';
import Badge from '@material-ui/core/Badge';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { Link } from 'react-router-dom';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import FileWork from './FileWork';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
});

const FileLineDeleteMutation = graphql`
  mutation FileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

const FileLineAskDeleteMutation = graphql`
  mutation FileLineAskDeleteMutation($workId: ID!) {
    deleteWork(id: $workId)
  }
`;

const FileLineImportAskJobMutation = graphql`
  mutation FileLineImportAskJobMutation($fileName: ID!) {
    askJobImport(fileName: $fileName) {
      ...FileLine_file
    }
  }
`;

class FileLineComponent extends Component {
  askForImportJob() {
    commitMutation({
      mutation: FileLineImportAskJobMutation,
      variables: { fileName: this.props.file.id },
      onCompleted: () => {
        MESSAGING$.notifySuccess('Import successfully asked');
      },
    });
  }

  executeRemove(mutation, variables) {
    commitMutation({
      mutation,
      variables,
      optimisticUpdater: (store) => {
        const fileStore = store.get(this.props.file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('progress', 'uploadStatus');
      },
      updater: (store) => {
        const fileStore = store.get(this.props.file.id);
        fileStore.setValue(0, 'lastModifiedSinceMin');
        fileStore.setValue('progress', 'uploadStatus');
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess('File successfully removed');
      },
    });
  }

  handleRemoveFile(name) {
    this.executeRemove(FileLineDeleteMutation, { fileName: name });
  }

  handleRemoveJob(id) {
    this.executeRemove(FileLineAskDeleteMutation, { workId: id });
  }

  render() {
    const {
      classes, fld, file, connectors,
    } = this.props;
    const { lastModifiedSinceMin, uploadStatus } = file;
    const isFail = uploadStatus === 'error' || uploadStatus === 'partial';
    const isProgress = uploadStatus === 'progress';
    const isOutdated = isProgress && lastModifiedSinceMin > 5;
    const isImportActive = () => connectors && filter((x) => x.data.active, connectors).length > 0;

    return (
      <ListItem
        dense={true}
        divider={true}
        classes={{ root: classes.item }}
        button={true}
        component={Link}
        disabled={isProgress}
        to={`/storage/view/${file.id}`}
        target="_blank"
        rel="noopener noreferrer"
      >
        <ListItemIcon>
          <FileOutline />
        </ListItemIcon>
        <ListItemText
          primary={file.name}
          secondary={file.lastModified ? fld(file.lastModified) : fld(moment())}
        />
        <ListItemSecondaryAction>
          <IconButton
            disabled={isProgress}
            href={`/storage/get/${file.id}`}
            aria-haspopup="true"
            color="primary"
          >
            <GetApp />
          </IconButton>
          {isFail || isOutdated ? (
            <IconButton
              disabled={isProgress}
              color="secondary"
              onClick={this.handleRemoveJob.bind(this, file.id)}
            >
              <Delete />
            </IconButton>
          ) : (
            <IconButton
              disabled={isProgress}
              color="primary"
              onClick={this.handleRemoveFile.bind(this, file.id)}
            >
              <Delete />
            </IconButton>
          )}
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

FileLineComponent.propTypes = {
  classes: PropTypes.object,
  fld: PropTypes.func,
  file: PropTypes.object.isRequired,
  connectors: PropTypes.array,
};

const FileLine = createFragmentContainer(FileLineComponent, {
  file: graphql`
    fragment FileLine_file on File {
      id
      name
      uploadStatus
      lastModified
      lastModifiedSinceMin
      metaData {
        category
        mimetype
      }
      ...FileWork_file
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(FileLine);
