import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles/index';
import Button from '@material-ui/core/Button';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import Typography from '@material-ui/core/Typography';
import DeleteIcon from '@material-ui/icons/Delete';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import { commitMutation } from '../../../../../relay/environment';
import inject18n from '../../../../../components/i18n';
import { toastGenericError } from '../../../../../utils/bakedToast';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  iconButton: {
    float: 'left',
    minWidth: '0px',
    marginRight: 15,
    padding: '7px',
  },
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const RemediationDeletionDarkLightMutation = graphql`
  mutation RemediationDeletionDarkLightMutation($id: ID!, $riskId: ID!) {
    deleteRiskResponse(id: $id, riskId: $riskId)
}
`;

class RemediationDeletion extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayDelete: false,
      displayEdit: false,
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

  handleOpenEdit() {
    this.setState({ displayEdit: true });
    this.handleClose();
  }

  handleCloseEdit() {
    this.setState({ displayEdit: false });
  }

  // submitDelete() {
  //   this.setState({ deleting: true });
  //   commitMutation({
  //     mutation: RemediationDeletionMutation,
  //     variables: {
  //       id: this.props.id,
  //     },
  //     config: [
  //       {
  //         type: 'NODE_DELETE',
  //         deletedIDFieldName: 'id',
  //       },
  //     ],
  //     onCompleted: () => {
  //       this.setState({ deleting: false });
  //       this.handleClose();
  //       this.props.history.push('/activities/risk assessment/risks');
  //     },
  //   });
  // }

  submitDelete() {
    const remediationIds = this.props.id.map((value) => (Array.isArray(value) ? value[0] : value));
    this.setState({ deleting: true });
    commitMutation({
      mutation: RemediationDeletionDarkLightMutation,
      variables: {
        id: remediationIds[0],
        riskId: this.props.riskId,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleClose();
        this.props.history.push(`/activities/risk assessment/risks/${this.props.riskId}/remediation`);
      },
      onError: () => toastGenericError('Failed to delete Remediation'),
    });
    // commitMutation({
    //   mutation: RemediationDeletionDarkLightMutation,
    //   variables: {
    //     id: this.props.id,
    //   },
    //   config: [
    //     {
    //       type: 'NODE_DELETE',
    //       deletedIDFieldName: 'id',
    //     },
    //   ],
    //   onCompleted: () => {
    //     this.setState({ deleting: false });
    //     this.handleClose();
    //     this.props.history.push('/activities/risk assessment/risks');
    //   },
    // });
  }

  render() {
    const {
      classes,
      t,
      id,
      isAllselected,
    } = this.props;
    return (
      <div className={classes.container}>
        {/* <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}> */}
        <Tooltip title={t('Delete')}>
          <Button
            variant="contained"
            onClick={this.handleOpenDelete.bind(this)}
            className={classes.iconButton}
            disabled={(Boolean(!id) && Boolean(!isAllselected))}
            color="primary"
            size="large"
          >
            <DeleteIcon fontSize="inherit" />
          </Button>
        </Tooltip>
        {/* </Security> */}
        <Dialog
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
        >
          <DialogContent>
            <Typography style={{
              fontSize: '18px',
              lineHeight: '24px',
              color: 'white',
            }} >
              {t('Are you sure you’d like to delete this Remediation?')}
            </Typography>
            <DialogContentText>
              {t('This action can’t be undone')}
            </DialogContentText>
          </DialogContent>
          <DialogActions className={classes.dialogActions}>
            <Button
              onClick={this.handleCloseDelete.bind(this)}
              disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="outlined"
              size="small"
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitDelete.bind(this)}
              color="primary"
              disabled={this.state.deleting}
              classes={{ root: classes.buttonPopover }}
              variant="contained"
              size="small"
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

RemediationDeletion.propTypes = {
  id: PropTypes.array,
  riskId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(RemediationDeletion);
