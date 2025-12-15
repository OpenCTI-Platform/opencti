import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import { MoreVertOutlined } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import DialogTitle from '@mui/material/DialogTitle';
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

const stixCoreRelationshipFromAndToPopoverDeletionMutation = graphql`
  mutation StixCoreRelationshipFromAndToPopoverDeletionMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

class StixCoreRelationshipFromAndToPopover extends Component {
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
    event.stopPropagation();
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  submitDelete() {
    const {
      fromId,
      toId,
      relationshipType,
      connectionKey,
      nodeId,
      paginationOptions,
    } = this.props;
    this.setState({ deleting: true });
    commitMutation({
      mutation: stixCoreRelationshipFromAndToPopoverDeletionMutation,
      variables: {
        fromId,
        toId,
        relationship_type: relationshipType,
      },
      updater: (store) => {
        if (typeof this.props.onDelete !== 'function') {
          const container = store.getRoot();
          const userProxy = store.get(container.getDataID());
          const conn = ConnectionHandler.getConnection(
            userProxy,
            connectionKey || 'Pagination_stixCoreRelationships',
            paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, nodeId);
        }
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
        if (typeof this.props.onDelete === 'function') {
          this.props.onDelete();
        }
      },
    });
  }

  render() {
    const { classes, t, disabled } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          disabled={disabled}
          color="primary"
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayDelete}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this relation?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitDelete.bind(this)}
              disabled={this.state.deleting}
            >
              {t('Confirm')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

StixCoreRelationshipFromAndToPopover.propTypes = {
  fromId: PropTypes.string,
  toId: PropTypes.string,
  relationshipType: PropTypes.string,
  nodeId: PropTypes.string,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onDelete: PropTypes.func,
  connectionKey: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipFromAndToPopover);
