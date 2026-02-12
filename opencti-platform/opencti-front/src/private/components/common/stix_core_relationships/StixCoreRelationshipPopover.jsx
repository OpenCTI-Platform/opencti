import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { MoreVertOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { deleteNodeFromContainer } from '../../../../utils/store';
import StixCoreRelationshipEdition from './StixCoreRelationshipEdition';

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

const stixCoreRelationshipPopoverDeletionMutation = graphql`
  mutation StixCoreRelationshipPopoverDeletionMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

class StixCoreRelationshipPopover extends Component {
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
      mutation: stixCoreRelationshipPopoverDeletionMutation,
      variables: {
        id: this.props.stixCoreRelationshipId,
      },
      updater: (store) => {
        if (typeof this.props.onDelete !== 'function') {
          const { stixCoreRelationshipId, paginationOptions, connectionKey, objectId } = this.props;
          const currentConnectionKey = connectionKey || 'Pagination_stixCoreRelationships';
          if (stixCoreRelationshipId) {
            deleteNodeFromContainer(
              store,
              objectId,
              currentConnectionKey,
              paginationOptions,
              stixCoreRelationshipId,
            );
          }
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
    const { classes, t, stixCoreRelationshipId, disabled, isCoverage } = this.props;
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
        {stixCoreRelationshipId && (
          <StixCoreRelationshipEdition
            variant="noGraph"
            stixCoreRelationshipId={stixCoreRelationshipId}
            open={this.state.displayUpdate}
            handleClose={this.handleCloseUpdate.bind(this)}
            noStoreUpdate={true}
            isCoverage={isCoverage}
          />
        )}
        <Dialog
          open={this.state.displayDelete}
          onClose={this.handleCloseDelete.bind(this)}
          title={t('Are you sure?')}
        >
          <DialogContentText>
            {t('Do you want to delete this relation?')}
          </DialogContentText>
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

StixCoreRelationshipPopover.propTypes = {
  stixCoreRelationshipId: PropTypes.string,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onDelete: PropTypes.func,
  connectionKey: PropTypes.string,
  objectId: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreRelationshipPopover);
