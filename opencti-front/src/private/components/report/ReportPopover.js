import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import MoreVert from '@material-ui/icons/MoreVert';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';

const styles = () => ({
  container: {
    margin: 0,
  },
});

function Transition(props) {
  return <Slide direction="up" {...props} />;
}

const ReportPopoverDeletionMutation = graphql`
    mutation ReportPopoverDeletionMutation($id: ID!) {
        reportEdit(id: $id) {
            delete
        }
    }
`;

class ReportPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
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
      mutation: ReportPopoverDeletionMutation,
      variables: {
        id: this.props.reportId,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleClose();
        this.props.history.push('/dashboard/reports/all');
      },
    });
  }

  render() {
    const { classes, t } = this.props;
    return (
      <div className={classes.container}>
        <IconButton onClick={this.handleOpen.bind(this)} aria-haspopup='true'>
          <MoreVert/>
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}>
          <MenuItem>{t('Export')}</MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>{t('Delete')}</MenuItem>
        </Menu>
        <Dialog
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this report?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={this.handleCloseDelete.bind(this)} color="primary" disabled={this.state.deleting}>
              {t('Cancel')}
            </Button>
            <Button onClick={this.submitDelete.bind(this)} color="primary" disabled={this.state.deleting}>
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

ReportPopover.propTypes = {
  reportId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ReportPopover);
