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
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import RoleEdition from './RoleEdition';
import withRouter from '../../../../utils/compat_router/withRouter';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const rolePopoverCleanContext = graphql`
  mutation RolePopoverCleanContextMutation($id: ID!) {
    roleEdit(id: $id) {
      contextClean {
        ...RoleEdition_role
      }
    }
  }
`;

const rolePopoverDeletionMutation = graphql`
  mutation RolePopoverDeletionMutation($id: ID!) {
    roleEdit(id: $id) {
      delete
    }
  }
`;

export const roleEditionQuery = graphql`
  query RolePopoverEditionQuery($id: String!) {
    role(id: $id) {
      ...RoleEdition_role
    }
  }
`;

class RolePopover extends Component {
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
    commitMutation({
      mutation: rolePopoverCleanContext,
      variables: { id: this.props.roleId },
    });
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
      mutation: rolePopoverDeletionMutation,
      variables: {
        id: this.props.roleId,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleClose();
        this.props.navigate('/dashboard/settings/accesses/roles');
      },
    });
  }

  render() {
    const { classes, t, roleId, disabled, isSensitive } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          size="large"
          style={{ marginTop: 3 }}
          disabled={disabled}
          color={isSensitive ? 'dangerZone' : 'primary'}
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
        <QueryRenderer
          query={roleEditionQuery}
          variables={{ id: roleId }}
          render={({ props }) => {
            if (props) {
              return (
                <RoleEdition
                  role={props.role}
                  handleClose={this.handleCloseUpdate.bind(this)}
                  open={this.state.displayUpdate}
                />
              );
            }
            return null;
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
              {t('Do you want to delete this role?')}
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

RolePopover.propTypes = {
  roleId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withRouter, withStyles(styles))(RolePopover);
