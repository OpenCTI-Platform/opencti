import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose,
  filter,
  pipe,
  split,
  drop,
  join,
  pathOr,
  propOr,
} from 'ramda';
import moment from 'moment';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { FileOutline, ProgressUpload } from 'mdi-material-ui';
import { DeleteOutlined, GetAppOutlined } from '@material-ui/icons';
import Tooltip from '@material-ui/core/Tooltip';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import CircularProgress from '@material-ui/core/CircularProgress';
import { Link } from 'react-router-dom';
import { commitMutation, MESSAGING$ } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import FileWork from './FileWork';

const styles = () => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
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
  mutation FileLineImportAskJobMutation($fileName: ID!, $context: String) {
    askJobImport(fileName: $fileName, context: $context) {
      ...FileLine_file
    }
  }
`;

class FileLineComponent extends Component {
  askForImportJob() {
    commitMutation({
      mutation: FileLineImportAskJobMutation,
      variables: { fileName: this.props.file.id, context: this.props.context },
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
      classes,
      t,
      fld,
      file,
      connectors,
      dense,
      disableImport,
      directDownload,
    } = this.props;
    const { lastModifiedSinceMin, uploadStatus } = file;
    const isFail = uploadStatus === 'error' || uploadStatus === 'partial';
    const isProgress = uploadStatus === 'progress';
    const isOutdated = isProgress && lastModifiedSinceMin > 1;
    const isImportActive = () => connectors && filter((x) => x.data.active, connectors).length > 0;
    const fileName = propOr('', 'name', file).includes('_')
      ? pipe(split('_'), drop(1), join('_'))(file.name)
      : file.name;
    const toolTip = pathOr('', ['metaData', 'listargs'], file);
    return (
      <div>
        <ListItem
          divider={true}
          dense={dense === true}
          classes={{ root: classes.item }}
          button={true}
          component={Link}
          disabled={isProgress}
          to={
            directDownload
              ? `/storage/get/${file.id}`
              : `/storage/view/${file.id}`
          }
          target="_blank"
          rel="noopener noreferrer"
        >
          <ListItemIcon>
            {isProgress ? <CircularProgress size={20} /> : <FileOutline />}
          </ListItemIcon>
          <Tooltip title={toolTip !== 'null' ? toolTip : ''}>
            <ListItemText
              classes={{ root: classes.itemText }}
              primary={fileName}
              secondary={fld(propOr(moment(), 'lastModified', file))}
            />
          </Tooltip>
          <ListItemSecondaryAction style={{ right: 0 }}>
            {!disableImport ? (
              <Tooltip title={t('Launch an import of this file')}>
                <span>
                  <IconButton disabled={isProgress || !isImportActive()}
                    onClick={this.askForImportJob.bind(this)}
                    aria-haspopup="true"
                    color="primary">
                    <ProgressUpload />
                  </IconButton>
                </span>
              </Tooltip>
            ) : (
              ''
            )}
            {!directDownload ? (
              <Tooltip title={t('Download this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    href={`/storage/get/${file.id}`}
                    aria-haspopup="true"
                    color="primary"
                  >
                    <GetAppOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            ) : (
              ''
            )}
            {isFail || isOutdated ? (
              <Tooltip title={t('Delete this file')}>
                <span>
                  <IconButton
                    color="secondary"
                    onClick={this.handleRemoveJob.bind(this, file.id)}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            ) : (
              <Tooltip title={t('Delete this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    color="primary"
                    onClick={this.handleRemoveFile.bind(this, file.id)}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </ListItemSecondaryAction>
        </ListItem>
        <FileWork file={file} />
      </div>
    );
  }
}

FileLineComponent.propTypes = {
  t: PropTypes.func,
  fld: PropTypes.func,
  classes: PropTypes.object,
  file: PropTypes.object.isRequired,
  connectors: PropTypes.array,
  dense: PropTypes.bool,
  disableImport: PropTypes.bool,
  directDownload: PropTypes.bool,
  context: PropTypes.string,
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
        listargs
      }
      ...FileWork_file
    }
  `,
});

export default compose(inject18n, withStyles(styles))(FileLine);
