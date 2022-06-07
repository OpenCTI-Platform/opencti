import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
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
      name
      uri
      token
      stream_id
      listen_deletion
      no_dependencies
      ssl_verify
    }
  }
`;

const syncPopoverStopMutation = graphql`
  mutation SyncPopoverStopMutation($id: ID!) {
    synchronizerStop(id: $id) {
      id
      name
      uri
      token
      stream_id
      listen_deletion
      no_dependencies
      ssl_verify
    }
  }
`;

const syncEditionQuery = graphql`
  query SyncPopoverEditionQuery($id: String!) {
    synchronizer(id: $id) {
      id
      name
      uri
      token
      stream_id
      listen_deletion
      no_dependencies
      ssl_verify
      current_state
    }
  }
`;

class SyncPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      displayStart: false,
      starting: false,
      displayStop: false,
      stopping: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenUpdate() {
    this.setState({ displayUpdate: true });
    this.handleClose();
  }

  handleCloseUpdate() {
    this.setState({ displayUpdate: false });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  handleOpenStart() {
    this.setState({ displayStart: true });
    this.handleClose();
  }

  handleCloseStart() {
    this.setState({ displayStart: false });
  }

  handleOpenStop() {
    this.setState({ displayStop: true });
    this.handleClose();
  }

  handleCloseStop() {
    this.setState({ displayStop: false });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: syncPopoverDeletionMutation,
      variables: {
        id: this.props.syncId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const payload = store.getRootField('synchronizerEdit');
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_synchronizers',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  submitStart() {
    this.setState({ starting: true });
    commitMutation({
      mutation: syncPopoverStartMutation,
      variables: {
        id: this.props.syncId,
      },
      onCompleted: () => {
        this.setState({ starting: false });
        this.handleCloseStart();
      },
    });
  }

  submitStop() {
    this.setState({ stopping: true });
    commitMutation({
      mutation: syncPopoverStopMutation,
      variables: {
        id: this.props.syncId,
      },
      onCompleted: () => {
        this.setState({ stopping: false });
        this.handleCloseStop();
      },
    });
  }

  render() {
    const { classes, t, syncId, running } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
        >
          <MoreVert />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          {!running && (
            <MenuItem onClick={this.handleOpenStart.bind(this)}>
              {t('Start')}
            </MenuItem>
          )}
          {running && (
            <MenuItem onClick={this.handleOpenStop.bind(this)}>
              {t('Stop')}
            </MenuItem>
          )}
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Drawer
          open={this.state.displayUpdate}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseUpdate.bind(this)}
        >
          <QueryRenderer
            query={syncEditionQuery}
            variables={{ id: syncId }}
            render={({ props }) => {
              if (props) {
                return (
                  <SyncEdition
                    synchronizer={props.synchronizer}
                    handleClose={this.handleCloseUpdate.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this synchronizer?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayStart}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseStart.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to start this synchronizer?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseStart.bind(this)}
              disabled={this.state.starting}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitStart.bind(this)}
              color="primary"
              disabled={this.state.starting}
            >
              {t('Start')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayStop}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseStop.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to stop this synchronizer?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseStop.bind(this)}
              disabled={this.state.stopping}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitStop.bind(this)}
              color="primary"
              disabled={this.state.stopping}
            >
              {t('Stop')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

SyncPopover.propTypes = {
  syncId: PropTypes.string,
  running: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(SyncPopover);
