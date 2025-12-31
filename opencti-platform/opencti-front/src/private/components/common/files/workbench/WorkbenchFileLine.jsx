import React from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@common/button/IconButton';
import { FileOutline } from 'mdi-material-ui';
import { DeleteOutlined, GetAppOutlined, WarningOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import CircularProgress from '@mui/material/CircularProgress';
import { Link } from 'react-router-dom';
import Slide from '@mui/material/Slide';
import Chip from '@mui/material/Chip';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import { WorkbenchFileLineDeleteMutation, workbenchLineFragment } from '../../../data/import/ImportWorkbenchesContent';
import FileWork from '../FileWork';
import { useFormatter } from '../../../../../components/i18n';
import { APP_BASE_PATH, commitMutation, MESSAGING$ } from '../../../../../relay/environment';
import { toB64 } from '../../../../../utils/String';
import useAuth from '../../../../../utils/hooks/useAuth';
import ItemMarkings from '../../../../../components/ItemMarkings';
import DeleteDialog from '../../../../../components/DeleteDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';

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
    width: '15%',
    display: 'flex',
    alignItems: 'center',
  },
  lastModified: {
    width: '10%',
  },
};

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const WorkbenchFileLineComponent = ({ classes, file, dense, directDownload, nested }) => {
  const { t_i18n, nsdt } = useFormatter();
  const { me } = useAuth();
  const deletion = useDeletion({});
  const { handleOpenDelete, handleCloseDelete } = deletion;

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
        MESSAGING$.notifySuccess(t_i18n('File successfully removed'));
      },
    });
  };

  const handleRemoveFile = () => {
    executeRemove(WorkbenchFileLineDeleteMutation, { fileName: file.id });
    handleCloseDelete();
  };

  const { uploadStatus, metaData } = file;
  const { errors } = metaData;
  const isFail = errors && errors.length > 0;
  const isProgress = uploadStatus === 'progress' || uploadStatus === 'wait';
  const isOutdated = uploadStatus === 'timeout';
  const file_markings = (file.objectMarking ?? []).map((o) => o.id);
  const fileMarkings = me.allowed_marking?.filter(({ id }) => (file_markings ?? []).includes(id)) ?? [];
  return (
    <>
      <ListItem
        divider={true}
        dense={dense === true}
        disablePadding
        secondaryAction={(
          <>
            {!directDownload && !isFail && (
              <Tooltip title={t_i18n('Download this file')}>
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
            <Tooltip title={t_i18n('Delete this workbench')}>
              <span>
                <IconButton
                  disabled={isProgress}
                  color={nested ? 'inherit' : 'primary'}
                  onClick={handleOpenDelete}
                  size="small"
                >
                  <DeleteOutlined fontSize="small" />
                </IconButton>
              </span>
            </Tooltip>
          </>
        )}
      >
        <ListItemButton
          classes={{ root: nested ? classes.itemNested : classes.item }}
          component={isOutdated ? null : Link}
          disabled={isProgress}
          to={`/dashboard/data/import/workbench/${toB64(file.id)}`}
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
            primary={(
              <>
                <div className={classes.bodyItem} style={inlineStyles.name}>
                  {file.name.replace('.json', '')}
                </div>
                <div className={classes.bodyItem} style={inlineStyles.creator_name}>
                  {file.metaData.creator?.name || t_i18n('Unknown')}
                </div>
                <div className={classes.bodyItem} style={inlineStyles.labels}>
                  {file.metaData.labels_text ? file.metaData.labels_text.split(';').map((label, index) => (
                    <Chip
                      key={index}
                      classes={{ root: classes.chipInList }}
                      color="primary"
                      variant="outlined"
                      label={label.trim()}
                    />
                  )) : null}
                </div>
                <div className={classes.bodyItem} style={inlineStyles.labels}>
                  <ItemMarkings variant="inList" markingDefinitions={fileMarkings} limit={1} />
                </div>
                <div className={classes.bodyItem} style={inlineStyles.lastModified}>
                  {nsdt(file.lastModified)}
                </div>
              </>
            )}
          />
        </ListItemButton>
      </ListItem>

      <FileWork file={file} />
      <DeleteDialog
        deletion={deletion}
        submitDelete={handleRemoveFile}
        message={t_i18n('Do you want to delete this workbench?')}
      />
    </>
  );
};

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

export default withStyles(styles)(WorkbenchFileLine);
