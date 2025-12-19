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
import StixNestedRefRelationshipEdition from './StixNestedRefRelationshipEdition';
import stopEvent from '../../../../utils/domEvent';

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

const stixNestedRefRelationshipPopoverDeletionMutation = graphql`
  mutation StixNestedRefRelationshipPopoverDeletionMutation($id: ID!) {
    stixRefRelationshipEdit(id: $id) {
      delete
    }
  }
`;

class StixNestedRefRelationshipPopover extends Component {
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
    stopEvent(event);
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose(event) {
    this.setState({ anchorEl: null });
    stopEvent(event);
  }

  handleOpenUpdate(event) {
    this.setState({ displayUpdate: true });
    this.handleClose(event);
  }

  handleCloseUpdate(event) {
    this.setState({ displayUpdate: false });
    stopEvent(event);
  }

  handleOpenDelete(event) {
    this.setState({ displayDelete: true });
    this.handleClose(event);
  }

  handleCloseDelete(event) {
    this.setState({ displayDelete: false });
    stopEvent(event);
  }

  submitDelete(event) {
    this.setState({ deleting: true });
    stopEvent(event);
    commitMutation({
      mutation: stixNestedRefRelationshipPopoverDeletionMutation,
      variables: {
        id: this.props.stixNestedRefRelationshipId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const payload = store.getRootField(
          'stixRefRelationshipEdit',
        );
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_stixNestedRefRelationships',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete(event);
      },
    });
  }

  render() {
    const { classes, t, stixNestedRefRelationshipId, disabled } = this.props;
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
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <StixNestedRefRelationshipEdition
          variant="noGraph"
          stixNestedRefRelationshipId={stixNestedRefRelationshipId}
          open={this.state.displayUpdate}
          handleClose={this.handleCloseUpdate.bind(this)}
        />
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

StixNestedRefRelationshipPopover.propTypes = {
  stixNestedRefRelationshipId: PropTypes.string,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixNestedRefRelationshipPopover);
