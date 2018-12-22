import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, head } from 'ramda';
import { withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation, QueryRenderer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles/index';
import Drawer from '@material-ui/core/Drawer';
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
import inject18n from '../../../components/i18n';
import environment from '../../../relay/environment';
import KillChainPhaseEdition from './KillChainPhaseEdition';

const styles = theme => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'hidden',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
});

function Transition(props) {
  return <Slide direction="up" {...props} />;
}

const killChainPhasePopoverDeletionMutation = graphql`
    mutation KillChainPhasePopoverDeletionMutation($id: ID!) {
        killChainPhaseEdit(id: $id) {
            delete
        }
    }
`;

const killChainPhaseEditionQuery = graphql`
    query KillChainPhasePopoverEditionQuery($id: String!) {
        killChainPhase(id: $id) {
            ...KillChainPhaseEdition_killChainPhase
        }
        me {
            ...KillChainPhaseEdition_me
        }
    }
`;

class KillChainPhasePopover extends Component {
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
    commitMutation(environment, {
      mutation: killChainPhasePopoverDeletionMutation,
      variables: {
        id: this.props.killChainPhaseId,
      },
      updater: (store) => {
        const payload = store.getRootField('killChainPhaseEdit');
        console.log(payload);
        /* const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
        const container = store.getRoot();
        sharedUpdater(store, container.getDataID(), this.props.paginationOptions, newEdge); */
      },
      onCompleted: (response, errors) => {
        this.setState({ deleting: false });
        if (errors) {
          const error = this.props.t(head(errors).message);
          console.log(error); // TODO Display the deletion error somewhere
        } else {
          this.handleCloseDelete();
        }
      },
    });
  }

  render() {
    const { classes, t, killChainPhaseId } = this.props;
    return (
      <div className={classes.container}>
        <IconButton onClick={this.handleOpen.bind(this)} aria-haspopup='true'>
          <MoreVert/>
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}
        >
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>{t('Update')}</MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>{t('Delete')}</MenuItem>
        </Menu>
        <Drawer open={this.state.displayUpdate} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleCloseUpdate.bind(this)}>
          <QueryRenderer
            environment={environment}
            query={killChainPhaseEditionQuery}
            variables={{ id: killChainPhaseId }}
            render={({ error, props }) => {
              if (error) { // Errors
                return <div> &nbsp; </div>;
              }
              if (props) { // Done
                return <KillChainPhaseEdition me={props.me} killChainPhase={props.killChainPhase} handleClose={this.handleCloseUpdate.bind(this)}/>;
              }
              // Loading
              return <div> &nbsp; </div>;
            }}
          />
        </Drawer>
        <Dialog
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this kill chain phase?')}
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

KillChainPhasePopover.propTypes = {
  killChainPhaseId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(KillChainPhasePopover);
