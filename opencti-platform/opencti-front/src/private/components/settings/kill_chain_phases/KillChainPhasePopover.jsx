import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import KillChainPhaseEdition from './KillChainPhaseEdition';
import Transition from '../../../../components/Transition';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const killChainPhasePopoverDeletionMutation = graphql`
  mutation KillChainPhasePopoverDeletionMutation($id: ID!) {
    killChainPhaseEdit(id: $id) {
      delete
    }
  }
`;

class KillChainPhasePopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
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

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: killChainPhasePopoverDeletionMutation,
      variables: {
        id: this.props.killChainPhaseId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const payload = store.getRootField('killChainPhaseEdit');
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_killChainPhases',
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

  render() {
    const { classes, t } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          size="large"
          color="primary"
        >
          <MoreVert />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <KillChainPhaseEdition
          killChainPhase={this.props.killChainPhase}
          handleClose={this.handleCloseUpdate.bind(this)}
          open={this.state.displayUpdate}
        />
        <Dialog
          open={this.state.displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this kill chain phase?')}
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
      </div>
    );
  }
}

KillChainPhasePopover.propTypes = {
  killChainPhase: PropTypes.object,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(KillChainPhasePopover);
