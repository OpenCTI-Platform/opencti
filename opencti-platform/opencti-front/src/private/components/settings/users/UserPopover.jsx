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
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import { withRouter } from 'react-router-dom';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import UserEdition from './UserEdition';
import Loader from '../../../../components/Loader';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

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
        this.props.history.push('/dashboard/settings/accesses/users');
      },
    });
  }

  render() {
    const { t, userId, disabled } = this.props;
    return (
      <>
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
        <QueryRenderer
          query={userEditionQuery}
          variables={{ id: userId }}
          render={({ props }) => {
            if (props) {
              return (
                <UserEdition
                  user={props.user}
                  open={this.state.displayUpdate}
                  handleClose={this.handleCloseUpdate.bind(this)}
                />
              );
            }
            return <Loader variant="inElement" />;
          }}
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
              {t('Do you want to delete this user?')}
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
