import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import fileDownload from 'js-file-download';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import React, { useState } from 'react';
import { fetchQuery, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, environment, QueryRenderer } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import Drawer from '../../common/drawer/Drawer';
import SyncEdition from './SyncEdition';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const syncPopoverDeletionMutation = graphql`
  mutation SyncPopoverDeletionMutation($id: ID!) {
    synchronizerEdit(id: $id) {
      delete
    }
  }
`;

const syncPopoverStartMutation = graphql`
  mutation SyncPopoverStartMutation($id: ID!) {
    synchronizerStart(id: $id) {
      id
    }
  }
`;

const syncPopoverStopMutation = graphql`
  mutation SyncPopoverStopMutation($id: ID!) {
    synchronizerStop(id: $id) {
      id
    }
  }
`;

const syncEditionQuery = graphql`
  query SyncPopoverEditionQuery($id: String!) {
    synchronizer(id: $id) {
      id
      name
      uri
      stream_id
      listen_deletion
      no_dependencies
      ssl_verify
      synchronized
      current_state_date
      user {
        id
        name
      }
    }
  }
`;

const syncPopoverExportQuery = graphql`
  query SyncPopoverExportQuery($id: String!) {
    synchronizer(id: $id) {
      name
      toConfigurationExport
    }
  }
`;

const SyncPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [displayStart, setDisplayStart] = useState(false);
  const [starting, setStarting] = useState(false);
  const [displayStop, setDisplayStop] = useState(false);
  const [stopping, setStopping] = useState(false);
  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const handleOpenStart = () => {
    setDisplayStart(true);
    handleClose();
  };

  const handleCloseStart = () => {
    setDisplayStart(false);
  };

  const handleOpenStop = () => {
    setDisplayStop(true);
    handleClose();
  };

  const handleCloseStop = () => {
    setDisplayStop(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: syncPopoverDeletionMutation,
      variables: {
        id: props.syncId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_synchronizers',
          props.paginationOptions,
          props.syncId,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
        if (props.onDeleteComplete) {
          props.onDeleteComplete();
        }
      },
    });
  };

  const submitStart = () => {
    setStarting(true);
    commitMutation({
      mutation: syncPopoverStartMutation,
      variables: {
        id: props.syncId,
      },
      onCompleted: () => {
        setStarting(false);
        handleCloseStart();
      },
    });
  };

  const submitStop = () => {
    setStopping(true);
    commitMutation({
      mutation: syncPopoverStopMutation,
      variables: {
        id: props.syncId,
      },
      onCompleted: () => {
        setStopping(false);
        handleCloseStop();
      },
    });
  };

  const exportSync = async () => {
    const { syncId } = props;

    const data = await fetchQuery(environment,
      syncPopoverExportQuery,
      { id: syncId },
    ).toPromise();

    if (data && data.synchronizer) {
      const { synchronizer } = data;

      const blob = new Blob(
        [synchronizer.toConfigurationExport],
        { type: 'application/json' },
      );

      const [day, month, year] = new Date()
        .toLocaleDateString('fr-FR')
        .split('/');

      const fileName = `${year}${month}${day}_synchronizer_${synchronizer.name}.json`;

      fileDownload(blob, fileName);
    }
  };

  const handleExport = async (event) => {
    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    setAnchorEl(null);
    await exportSync();
  };

  const { classes, syncId, running } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        {!running && (
          <MenuItem onClick={handleOpenStart}>
            {t_i18n('Start')}
          </MenuItem>
        )}
        {running && (
          <MenuItem onClick={handleOpenStop}>
            {t_i18n('Stop')}
          </MenuItem>
        )}
        <MenuItem disabled={running} onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleExport}>
          {t_i18n('Export')}
        </MenuItem>
        <MenuItem disabled={running} onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <Drawer
        open={displayUpdate}
        onClose={handleCloseUpdate}
        title={t_i18n('Update an OpenCTI stream')}
      >
        <QueryRenderer
          query={syncEditionQuery}
          variables={{ id: syncId }}
          render={({ props }) => {
            if (props) {
              return (
                <SyncEdition
                  synchronizer={props.synchronizer}
                />
              );
            }
            return <div />;
          }}
        />
      </Drawer>
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this OpenCTI stream?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayStart}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseStart}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to start this OpenCTI stream?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseStart}
            disabled={starting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitStart}
            disabled={starting}
          >
            {t_i18n('Start')}
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayStop}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseStop}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to stop this OpenCTI stream?')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseStop}
            disabled={stopping}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitStop}
            disabled={stopping}
          >
            {t_i18n('Stop')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

SyncPopover.propTypes = {
  syncId: PropTypes.string,
  running: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  onDeleteComplete: PropTypes.func,
};

export default compose(withStyles(styles))(SyncPopover);
