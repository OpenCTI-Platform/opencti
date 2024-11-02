import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import Drawer from '@mui/material/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import ToggleButton from '@mui/material/ToggleButton';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import withRouter from '../../../../utils/compat_router/withRouter';
import inject18n from '../../../../components/i18n';
import { QueryRenderer, commitMutation } from '../../../../relay/environment';
import { stixCyberObservableEditionQuery } from './StixCyberObservableEdition';
import StixCyberObservableEditionContainer from './StixCyberObservableEditionContainer';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import Transition from '../../../../components/Transition';

const styles = (theme) => ({
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

const StixCyberObservablePopoverDeletionMutation = graphql`
  mutation StixCyberObservablePopoverDeletionMutation($id: ID!) {
    stixCyberObservableEdit(id: $id) {
      delete
    }
  }
`;

class StixCyberObservablePopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayDelete: false,
      displayEdit: false,
      displayEnroll: false,
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
      mutation: StixCyberObservablePopoverDeletionMutation,
      variables: {
        id: this.props.stixCyberObservableId,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleClose();
        this.props.navigate(
          `/dashboard/observations/${
            this.props.isArtifact ? 'artifacts' : 'observables'
          }`,
        );
      },
    });
  }

  handleOpenEdit() {
    this.setState({ displayEdit: true });
    this.handleClose();
  }

  handleCloseEdit() {
    this.setState({ displayEdit: false });
  }

  handleOpenEnroll() {
    this.setState({ displayEnroll: true });
    this.handleClose();
  }

  handleCloseEnroll() {
    this.setState({ displayEnroll: false });
  }

  render() {
    const { classes, t, stixCyberObservableId } = this.props;
    return (
      <>
        <ToggleButton
          value="popover"
          size="small"

          onClick={this.handleOpen.bind(this)}
        >
          <MoreVert fontSize="small" color="primary" />
        </ToggleButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          <MenuItem onClick={this.handleOpenEdit.bind(this)}>
            {t('Update')}
          </MenuItem>
          <Security needs={[KNOWLEDGE_KNENRICHMENT]}>
            <MenuItem onClick={this.handleOpenEnroll.bind(this)}>
              {t('Enroll in playbook')}
            </MenuItem>
          </Security>
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem onClick={this.handleOpenDelete.bind(this)}>
              {t('Delete')}
            </MenuItem>
          </Security>
        </Menu>
        <StixCoreObjectEnrollPlaybook stixCoreObjectId={stixCyberObservableId} open={this.state.displayEnroll} handleClose={this.handleCloseEnroll.bind(this)} />
        <Dialog
          open={this.state.displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this observable?')}
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
        <Drawer
          open={this.state.displayEdit}
          anchor="right"
          sx={{ zIndex: 1202 }}
          elevation={1}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseEdit.bind(this)}
        >
          <QueryRenderer
            query={stixCyberObservableEditionQuery}
            variables={{ id: stixCyberObservableId }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCyberObservableEditionContainer
                    stixCyberObservable={props.stixCyberObservable}
                    handleClose={this.handleCloseEdit.bind(this)}
                  />
                );
              }
              return <div />;
            }}
          />
        </Drawer>
      </>
    );
  }
}

StixCyberObservablePopover.propTypes = {
  stixCyberObservableId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  navigate: PropTypes.func,
  isArtifact: PropTypes.bool,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixCyberObservablePopover);
