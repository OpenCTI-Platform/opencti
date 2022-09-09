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
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

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

export const containerStixCoreObjectPopoverRemoveMutation = graphql`
  mutation ContainerStixCoreObjectPopoverRemoveMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    containerEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

export const containerStixCoreObjectPopoverDeleteMutation = graphql`
  mutation ContainerStixCoreObjectPopoverDeleteMutation($id: ID!) {
    stixCoreObjectEdit(id: $id) {
      delete
    }
  }
`;

class ContainerStixCoreObjectPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayRemove: false,
      displayDelete: false,
      removing: false,
      deleting: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenRemove() {
    this.setState({ displayRemove: true });
    this.handleClose();
  }

  handleCloseRemove() {
    this.setState({ removing: false, displayRemove: false });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ deleting: false, displayDelete: false });
  }

  submitRemove() {
    const {
      containerId,
      toId,
      relationshipType,
      paginationKey,
      paginationOptions,
    } = this.props;
    this.setState({ removing: true });
    commitMutation({
      mutation: containerStixCoreObjectPopoverRemoveMutation,
      variables: {
        id: containerId,
        toId,
        relationship_type: relationshipType,
      },
      updater: (store) => {
        if (toId) {
          const conn = ConnectionHandler.getConnection(
            store.get(containerId),
            paginationKey,
            paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, toId);
        }
      },
      onCompleted: () => {
        this.handleCloseRemove();
      },
    });
  }

  submitDelete() {
    const { containerId, toId, paginationKey, paginationOptions } = this.props;
    this.setState({ deleting: true });
    commitMutation({
      mutation: containerStixCoreObjectPopoverDeleteMutation,
      variables: {
        id: toId,
      },
      updater: (store) => {
        if (toId) {
          const conn = ConnectionHandler.getConnection(
            store.get(containerId),
            paginationKey,
            paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, toId);
        }
      },
      onCompleted: () => {
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
          <MenuItem onClick={this.handleOpenRemove.bind(this)}>
            {t('Remove')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayRemove}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseRemove.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove the entity from this container?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseRemove.bind(this)}
              disabled={this.state.removing}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitRemove.bind(this)}
              disabled={this.state.removing}
            >
              {t('Remove')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this entity?')}
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

ContainerStixCoreObjectPopover.propTypes = {
  containerId: PropTypes.string,
  toId: PropTypes.string,
  relationshipType: PropTypes.string,
  paginationKey: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ContainerStixCoreObjectPopover);
