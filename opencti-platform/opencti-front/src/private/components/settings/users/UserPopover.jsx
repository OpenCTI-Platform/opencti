import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogTitle from '@mui/material/DialogTitle';
import withRouter from '../../../../utils/compat_router/withRouter';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import UserEdition from './UserEdition';
import Transition from '../../../../components/Transition';

const userPopoverDeletionMutation = graphql`
  mutation UserPopoverDeletionMutation($id: ID!) {
    userEdit(id: $id) {
      delete
    }
  }
`;

export const userEditionQuery = graphql`
  query UserPopoverEditionQuery($id: String!) {
    user(id: $id) {
      ...UserEdition_user
    }
  }
`;

class UserPopover extends Component {
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
      mutation: userPopoverDeletionMutation,
      variables: {
        id: this.props.userId,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleClose();
        this.props.navigate('/dashboard/settings/accesses/users');
      },
    });
  }

  render() {
    const { t, disabled, userEditionData } = this.props;
    return (
      <>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
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
          <MenuItem
            onClick={this.handleOpenDelete.bind(this)}
            disabled={disabled}
          >
            {t('Delete')}
          </MenuItem>
        </Menu>
        <UserEdition
          userEditionData={userEditionData}
          open={this.state.displayUpdate}
          handleClose={this.handleCloseUpdate.bind(this)}
        />
        <Dialog
          open={this.state.displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogTitle>{t('Do you want to delete this user?')}</DialogTitle>
          <DialogContent dividers>
            <ul>
              <li>{t('All notifications, triggers and digests associated with the user will be deleted.')}</li>
              <li>{t('All investigations and dashboard where the user is the only admin, will be deleted.')}</li>
            </ul>
            {t('If you want to keep the associated information, we recommend deactivating the user instead.')}
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
      </>
    );
  }
}

UserPopover.propTypes = {
  userId: PropTypes.string,
  paginationOptions: PropTypes.object,
  t: PropTypes.func,
  disabled: PropTypes.bool,
};

export default compose(inject18n, withRouter)(UserPopover);
