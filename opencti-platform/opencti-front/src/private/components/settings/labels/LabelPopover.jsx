import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Component } from 'react';
import { graphql } from 'react-relay';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import LabelEdition from './LabelEdition';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const labelPopoverDeletionMutation = graphql`
  mutation LabelPopoverDeletionMutation($id: ID!) {
    labelEdit(id: $id) {
      delete
    }
  }
`;

class LabelPopover extends Component {
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
      mutation: labelPopoverDeletionMutation,
      variables: {
        id: this.props.label.id,
      },
      updater: (store) => deleteNode(
        store,
        'Pagination_labels',
        this.props.paginationOptions,
        this.props.label.id,
      ),
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
        <LabelEdition
          label={this.props.label}
          handleClose={this.handleCloseUpdate.bind(this)}
          open={this.state.displayUpdate}
        />
        <Dialog
          open={this.state.displayDelete}
          onClose={this.handleCloseDelete.bind(this)}
          title={t('Are you sure?')}
          size="small"
        >
          <DialogContentText>
            {t('Do you want to delete this label?')}
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

LabelPopover.propTypes = {
  label: PropTypes.object,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(LabelPopover);
