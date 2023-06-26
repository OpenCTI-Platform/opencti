import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import { FileOutline } from 'mdi-material-ui';
import {
  DeleteOutlined,
  GetAppOutlined,
  WarningOutlined,
} from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItem from '@mui/material/ListItem';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import CircularProgress from '@mui/material/CircularProgress';
import { Link } from 'react-router-dom';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Slide from '@mui/material/Slide';
import Chip from '@mui/material/Chip';
import FileWork from '../FileWork';
import inject18n from '../../../../../components/i18n';
import {
  APP_BASE_PATH,
  commitMutation,
  MESSAGING$,
} from '../../../../../relay/environment';
import { toB64 } from '../../../../../utils/String';

const styles = (theme) => ({
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
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 10,
  },
  linesContainer: {
    marginTop: 10,
  },
  itemHead: {
    paddingLeft: 10,
    textTransform: 'uppercase',
    cursor: 'pointer',
  },
  item: {
    paddingLeft: 10,
    height: 50,
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  inputLabel: {
    float: 'left',
  },
  sortIcon: {
    float: 'left',
    margin: '-5px 0 0 15px',
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '40%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  creator_name: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  labels: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  lastModified: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const WorkbenchFileLineDeleteMutation = graphql`
  mutation WorkbenchFileLineDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

const WorkbenchFileLineAskDeleteMutation = graphql`
  mutation WorkbenchFileLineAskDeleteMutation($workId: ID!) {
    workEdit(id: $workId) {
      delete
    }
  }
`;

class WorkbenchFileLineComponent extends Component {
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
    this.executeRemove(WorkbenchFileLineDeleteMutation, { fileName: name });
    this.setState({ displayDelete: false });
  }

  handleRemoveJob(id) {
    this.executeRemove(WorkbenchFileLineAskDeleteMutation, { workId: id });
  }

  render() {
    const { classes, t, file, dense, directDownload, nested, nsdt } = this.props;
    const { displayDelete } = this.state;
    const { uploadStatus, metaData } = file;
    const { errors } = metaData;
    const isFail = errors.length > 0;
    const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
    const isOutdated = uploadStatus === 'timeout';
    return (
      <div>
        <ListItem
          divider={true}
          dense={dense === true}
          classes={{ root: nested ? classes.itemNested : classes.item }}
          button={true}
          component={isOutdated ? null : Link}
          disabled={isProgress}
          to={`/dashboard/import/pending/${toB64(file.id)}`}
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
            primary={
              <div>
                <div className={classes.bodyItem} style={inlineStyles.name}>
                  {file.name.replace('.json', '')}
                </div>
                <div
                  className={classes.bodyItem}
                  style={inlineStyles.creator_name}
                >
                  {file.metaData.creator?.name || t('Unknown')}
                </div>
                <div className={classes.bodyItem} style={inlineStyles.labels}>
                  {(file.metaData.labels || []).map((n) => (
                    <Chip
                      key={n}
                      classes={{ root: classes.chipInList }}
                      color="primary"
                      variant="outlined"
                      label={n}
                    />
                  ))}
                </div>
                <div
                  className={classes.bodyItem}
                  style={inlineStyles.lastModified}
                >
                  {nsdt(file.lastModified)}
                </div>
              </div>
            }
          />
          <ListItemSecondaryAction>
            {!directDownload && !isFail && (
              <Tooltip title={t('Download this file')}>
                <span>
                  <IconButton
                    disabled={isProgress}
                    href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(
                      file.id,
                    )}`}
                    aria-haspopup="true"
                    color={nested ? 'inherit' : 'primary'}
                    size="large"
                  >
                    <GetAppOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            )}
            <Tooltip title={t('Delete this workbench')}>
              <span>
                <IconButton
                  disabled={isProgress}
                  color={nested ? 'inherit' : 'primary'}
                  onClick={this.handleOpenDelete.bind(this)}
                  size="large"
                >
                  <DeleteOutlined />
                </IconButton>
              </span>
            </Tooltip>
          </ListItemSecondaryAction>
        </ListItem>
        <FileWork file={file} />
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={displayDelete}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this workbench?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseDelete.bind(this)}>
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.handleRemoveFile.bind(this, file.id)}
              color="secondary"
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

WorkbenchFileLineComponent.propTypes = {
  t: PropTypes.func,
  fld: PropTypes.func,
  classes: PropTypes.object,
  file: PropTypes.object.isRequired,
  connectors: PropTypes.array,
  dense: PropTypes.bool,
  directDownload: PropTypes.bool,
  handleOpenImport: PropTypes.func,
  nested: PropTypes.bool,
};

const WorkbenchFileLine = createFragmentContainer(WorkbenchFileLineComponent, {
  file: graphql`
    fragment WorkbenchFileLine_file on File {
      id
      name
      uploadStatus
      lastModified
      lastModifiedSinceMin
      metaData {
        mimetype
        list_filters
        labels
        messages {
          timestamp
          message
        }
        errors {
          timestamp
          message
        }
        creator {
          name
        }
        entity_id
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
          ... on Grouping {
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
          ... on AdministrativeArea {
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

export default compose(inject18n, withStyles(styles))(WorkbenchFileLine);
