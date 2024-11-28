import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import { FileOutline } from 'mdi-material-ui';
import { DeleteOutlined, GetAppOutlined, WarningOutlined } from '@mui/icons-material';
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
import { WorkbenchFileLineDeleteMutation, workbenchLineFragment } from '../../../data/import/ImportWorkbenchesContent';
import FileWork from '../FileWork';
import inject18n from '../../../../../components/i18n';
import { APP_BASE_PATH, commitMutation, MESSAGING$ } from '../../../../../relay/environment';
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
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
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
    width: '35%',
  },
  creator_name: {
    width: '20%',
  },
  labels: {
    width: '20%',
  },
  lastModified: {
    width: '20%',
  },
};

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
    const isFail = errors && errors.length > 0;
    const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
    const isOutdated = uploadStatus === 'timeout';
    return (
      <>
        <ListItem
          divider={true}
          dense={dense === true}
          classes={{ root: nested ? classes.itemNested : classes.item }}
          button={true}
          component={isOutdated ? null : Link}
          disabled={isProgress}
          to={`/dashboard/data/import/pending/${toB64(file.id)}`}
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
            style={{ paddingRight: 10 }}
            primary={
              <>
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
                  {file.metaData.labels_text
                    ? file.metaData.labels_text.split(';').map((label, index) => (
                      <Chip
                        key={index}
                        classes={{ root: classes.chipInList }}
                        color="primary"
                        variant="outlined"
                        label={label.trim()}
                      />
                    ))
                    : null}
                </div>
                <div
                  className={classes.bodyItem}
                  style={inlineStyles.lastModified}
                >
                  {nsdt(file.lastModified)}
                </div>
              </>
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
                    size="small"
                  >
                    <GetAppOutlined fontSize="small" />
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
                  size="small"
                >
                  <DeleteOutlined fontSize="small" />
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
      </>
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
  nested: PropTypes.bool,
};

const WorkbenchFileLine = createFragmentContainer(WorkbenchFileLineComponent, {
  file: workbenchLineFragment,
});

export default compose(inject18n, withStyles(styles))(WorkbenchFileLine);
