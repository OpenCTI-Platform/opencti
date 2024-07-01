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
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import LabelEdition from './LabelEdition';
import Transition from '../../../../components/Transition';
import { deleteNode } from '../../../../utils/store';

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

const labelEditionQuery = graphql`
  query LabelPopoverEditionQuery($id: String!) {
    label(id: $id) {
      ...LabelEdition_label
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
        id: this.props.labelId,
      },
      updater: (store) => deleteNode(
        store,
        'Pagination_labels',
        this.props.paginationOptions,
        this.props.labelId,
      ),
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  render() {
    const { classes, t, labelId } = this.props;
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
        <QueryRenderer
          query={labelEditionQuery}
          variables={{ id: labelId }}
          render={({ props }) => {
            if (props) {
              return (
                <LabelEdition
                  label={props.label}
                  handleClose={this.handleCloseUpdate.bind(this)}
                  open={this.state.displayUpdate}
                />
              );
            }
            return <div />;
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
              {t('Do you want to delete this label?')}
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

LabelPopover.propTypes = {
  labelId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(LabelPopover);
