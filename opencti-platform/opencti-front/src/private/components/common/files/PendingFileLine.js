import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter, propOr } from 'ramda';
import moment from 'moment';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import IconButton from '@material-ui/core/IconButton';
import { FileOutline } from 'mdi-material-ui';
import {
  DeleteOutlined,
  CheckCircleOutlined,
  CancelOutlined,
  GetAppOutlined,
  WarningOutlined,
} from '@material-ui/icons';
import Tooltip from '@material-ui/core/Tooltip';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItem from '@material-ui/core/ListItem';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import CircularProgress from '@material-ui/core/CircularProgress';
import { Link } from 'react-router-dom';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import DialogActions from '@material-ui/core/DialogActions';
import Button from '@material-ui/core/Button';
import Slide from '@material-ui/core/Slide';
import FileWork from './FileWork';
import inject18n from '../../../../components/i18n';
import {
  APP_BASE_PATH,
  commitMutation,
  MESSAGING$,
} from '../../../../relay/environment';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemNested: {
    paddingLeft: theme.spacing(4),
    height: 50,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const PendingFileLineDeleteMutation = graphql`
  mutation PendingFileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

const PendingFileLineAskDeleteMutation = graphql`
  mutation PendingFileLineAskDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

class PendingFileLineComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { displayDelete: false };
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  executeRemove(mutation, variables) {
    const { t } = this.props;
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
        MESSAGING$.notifySuccess(t('File successfully removed'));
      },
    });
  }

  handleRemoveFile(name) {
    this.executeRemove(PendingFileLineDeleteMutation, { fileName: name });
    this.setState({ displayDelete: false });
  }

  handleRemoveJob(id) {
    this.executeRemove(PendingFileLineAskDeleteMutation, { workId: id });
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
      handleOpenImport,
      nested,
    } = this.props;
    const { displayDelete } = this.state;
    const { uploadStatus, metaData } = file;
    const { errors } = metaData;
    const isFail = errors.length > 0;
    const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
    const isOutdated = uploadStatus === 'timeout';
    const isImportActive = () => connectors && filter((x) => x.data.active, connectors).length > 0;
    const isDeleteActive = file.works.length > 0;
    return (
      <div>
        <ListItem
          divider={true}
          dense={dense === true}
          classes={{ root: nested ? classes.itemNested : classes.item }}
          button={true}
          component={isOutdated ? null : Link}
          disabled={isProgress}
          to={`/dashboard/import/pending/${Buffer.from(
            file.id,
            'binary',
          ).toString('base64')}`}
        >
          <ListItemIcon>
            {isProgress && (
              <CircularProgress
                size={20}
                color={nested ? 'primary' : 'inherit'}
              />
            )}
            {!isProgress && (isFail || isOutdated) && (
              <WarningOutlined
                color={nested ? 'primary' : 'inherit'}
                style={{ fontSize: 15, color: '#f44336' }}
              />
            )}
            {!isProgress && !isFail && !isOutdated && (
              <FileOutline color={nested ? 'primary' : 'inherit'} />
            )}
          </ListItemIcon>
          <ListItemText
            classes={{ root: classes.itemText }}
            primary={file.name}
            secondary={fld(propOr(moment(), 'lastModified', file))}
          />
          <ListItemSecondaryAction>
            {!directDownload && !isFail && (
              <Tooltip title={t('Download this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    href={`${APP_BASE_PATH}/storage/get/${file.id}`}
                    aria-haspopup="true"
                    color={nested ? 'inherit' : 'primary'}
                  >
                    <GetAppOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {!disableImport && (
              <Tooltip title={t('Validate this pending bundle')}>
                <span>
                  <IconButton
                    disabled={isProgress || !isImportActive() || isDeleteActive}
                    onClick={handleOpenImport.bind(this, file)}
                    aria-haspopup="true"
                    color={nested ? 'inherit' : 'primary'}
                  >
                    <CheckCircleOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {isDeleteActive ? (
              <Tooltip title={t('Delete this pending bundle')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    color={nested ? 'inherit' : 'primary'}
                    onClick={this.handleOpenDelete.bind(this)}
                  >
                    <DeleteOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            ) : (
              <Tooltip title={t('Drop this pending bundle')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    color={nested ? 'inherit' : 'primary'}
                    onClick={this.handleOpenDelete.bind(this)}
                  >
                    <CancelOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </ListItemSecondaryAction>
        </ListItem>
        <FileWork file={file} />
        <Dialog
          open={displayDelete}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to drop this bundle?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseDelete.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoveFile.bind(this, file.id)}
              color="primary"
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

PendingFileLineComponent.propTypes = {
  t: PropTypes.func,
  fld: PropTypes.func,
  classes: PropTypes.object,
  file: PropTypes.object.isRequired,
  connectors: PropTypes.array,
  dense: PropTypes.bool,
  disableImport: PropTypes.bool,
  directDownload: PropTypes.bool,
  handleOpenImport: PropTypes.func,
  nested: PropTypes.bool,
};

const PendingFileLine = createFragmentContainer(PendingFileLineComponent, {
  file: graphql`
    fragment PendingFileLine_file on File {
      id
      name
      uploadStatus
      lastModified
      lastModifiedSinceMin
      metaData {
        mimetype
        list_filters
        messages {
          timestamp
          message
        }
        errors {
          timestamp
          message
        }
        entity {
          ... on AttackPattern {
            name
          }
          ... on Campaign {
            name
          }
          ... on Report {
            name
          }
          ... on CourseOfAction {
            name
          }
          ... on Individual {
            name
          }
          ... on Organization {
            name
          }
          ... on Sector {
            name
          }
          ... on System {
            name
          }
          ... on Indicator {
            name
          }
          ... on Infrastructure {
            name
          }
          ... on IntrusionSet {
            name
          }
          ... on Position {
            name
          }
          ... on City {
            name
          }
          ... on Country {
            name
          }
          ... on Region {
            name
          }
          ... on Malware {
            name
          }
          ... on ThreatActor {
            name
          }
          ... on Tool {
            name
          }
          ... on Vulnerability {
            name
          }
          ... on Incident {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
        }
      }
      works {
        id
      }
      ...FileWork_file
    }
  `,
});

export default compose(inject18n, withStyles(styles))(PendingFileLine);
