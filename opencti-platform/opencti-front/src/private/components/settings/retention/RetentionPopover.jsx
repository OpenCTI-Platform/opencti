import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import MoreVert from '@mui/icons-material/MoreVert';
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
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import RetentionEdition from './RetentionEdition';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const retentionPopoverDeletionMutation = graphql`
  mutation RetentionPopoverDeletionMutation($id: ID!) {
    retentionRuleEdit(id: $id) {
      delete
    }
  }
`;

const retentionPopoverFieldPatchMutation = graphql`
  mutation RetentionPopoverFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    retentionRuleEdit(id: $id) {
      fieldPatch(input: $input) {
        id
        active
      }
    }
  }
`;

const retentionEditionQuery = graphql`
  query RetentionPopoverEditionQuery($id: String!) {
    retentionRule(id: $id) {
      id
      name
      max_retention
      filters
      active
      ...RetentionEdition_retentionRule
    }
  }
`;

class RetentionPopover extends Component {
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
      mutation: retentionPopoverDeletionMutation,
      variables: {
        id: this.props.retentionRuleId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_retentionRules',
          this.props.paginationOptions,
          this.props.retentionRuleId,
        );
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  submitToggleActive(currentActive) {
    commitMutation({
      mutation: retentionPopoverFieldPatchMutation,
      variables: {
        id: this.props.retentionRuleId,
        input: [{ key: 'active', value: [String(!currentActive)] }],
      },
    });
    this.handleClose();
  }

  render() {
    const { classes, t, retentionRuleId } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          color="primary"
        >
          <MoreVert />
        </IconButton>
        <QueryRenderer
          query={retentionEditionQuery}
          variables={{ id: retentionRuleId }}
          render={({ props }) => {
            if (props) {
              const { retentionRule } = props;
              return (
                <>
                  <Menu
                    anchorEl={this.state.anchorEl}
                    open={Boolean(this.state.anchorEl)}
                    onClose={this.handleClose.bind(this)}
                  >
                    <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
                      {t('Update')}
                    </MenuItem>
                    <MenuItem onClick={() => this.submitToggleActive(retentionRule?.active)}>
                      {retentionRule?.active ? t('Deactivate') : t('Activate')}
                    </MenuItem>
                    <MenuItem onClick={this.handleOpenDelete.bind(this)}>
                      {t('Delete')}
                    </MenuItem>
                  </Menu>
                  <RetentionEdition
                    retentionRule={retentionRule}
                    handleClose={this.handleCloseUpdate.bind(this)}
                    open={this.state.displayUpdate}
                  />
                </>
              );
            }
            return (
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
            );
          }}
        />
        <Dialog
          open={this.state.displayDelete}
          onClose={this.handleCloseDelete.bind(this)}
          title={t('Are you sure?')}
        >
          <DialogContentText>
            {t('Do you want to delete this retention policy?')}
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

RetentionPopover.propTypes = {
  retentionRuleId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(RetentionPopover);
