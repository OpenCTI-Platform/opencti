import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles/index';
import Button from '@material-ui/core/Button';
import Drawer from '@material-ui/core/Drawer';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import AddCircleOutline from '@material-ui/icons/AddCircleOutline';
import Slide from '@material-ui/core/Slide';
import DeleteIcon from '@material-ui/icons/Delete';
import EditIcon from '@material-ui/icons/Edit';
import Tooltip from '@material-ui/core/Tooltip';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import inject18n from '../../../../components/i18n';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import NetworkEditionContainer from './NetworkEditionContainer';
import { networkEditionQuery, networkEditionDarkLightQuery } from './NetworkEdition';
import Loader from '../../../../components/Loader';
import Security, {
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
} from '../../../../utils/Security';

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
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const NetworkOperationsDeletionMutation = graphql`
  mutation NetworkOperationsDeletionMutation($id: ID!) {
    threatActorEdit(id: $id) {
      delete
    }
  }
`;

const NetworkOperationsDeletionDarkLightMutation = graphql`
  mutation NetworkOperationsDeletionDarkLightMutation($id: ID!) {
    deleteNetworkAsset(id: $id)
}
`;

class NetworkOperations extends Component {
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
  //     mutation: NetworkOperationsDeletionMutation,
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
  //       this.props.history.push('/dashboard/assets/network');
  //     },
  //   });
  // }

  submitDelete() {
    this.setState({ deleting: true });
    CM(environmentDarkLight, {
      mutation: NetworkOperationsDeletionDarkLightMutation,
      variables: {
        id: this.props.id,
      },
      onCompleted: (data) => {
        this.setState({ deleting: false });
        console.log('NetworkOperationsDeletionDarkLightMutationData', data);
        this.handleClose();
        this.props.history.push('/dashboard/assets/network');
      },
      onError: (err) => console.log('NetwrokOperationsDeletionDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: NetworkOperationsDeletionDarkLightMutation,
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
    //     this.props.history.push('/dashboard/assets/network');
    //   },
    // });
  }

  render() {
    const {
      classes,
      t,
      id,
      handleOpenEdit,
      isAllselected,
    } = this.props;
    return (
      <div className={classes.container}>
        <Tooltip title={t('Edit')}>
          <Button
            variant="contained"
            onClick={handleOpenEdit}
            className={classes.iconButton}
            disabled={Boolean(!id)}
            color="primary"
            size="large"
          >
            <EditIcon fontSize="inherit"/>
          </Button>
        </Tooltip>
        <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
          <Tooltip title={t('Delete')}>
          <Button
            variant="contained"
            onClick={this.handleOpenDelete.bind(this)}
            className={classes.iconButton}
            disabled={Boolean(!id) && Boolean(!isAllselected)}
            color="primary"
            size="large"
          >
              <DeleteIcon fontSize="inherit"/>
            </Button>
          </Tooltip>
        </Security>
        <Dialog
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this network?')}
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
              onClick={this.submitDelete.bind(this)}
              color="primary"
              disabled={this.state.deleting}
            >
              {t('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Drawer
          open={this.state.displayEdit}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseEdit.bind(this)}
        >
          {/* <QueryRenderer
            query={networkEditionQuery}
            variables={{ id }}
            render={({ props }) => {
              console.log('NetworkEditionContainer', props);
              if (props) {
                return (
                  <NetworkEditionContainer
                    network={props.threatActor}
                    handleClose={this.handleCloseEdit.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          /> */}
          <QR
            environment={environmentDarkLight}
            query={networkEditionDarkLightQuery}
            variables={{ id }}
            render={({ error, props }) => {
              console.log(`NetworkEditionDarkLightQuery Error ${error} OR Props ${JSON.stringify(props)}`);
              if (props) {
                return (
                  <NetworkEditionContainer
                    network={props.networkAsset}
                    handleClose={this.handleCloseEdit.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
      </div>
    );
  }
}

NetworkOperations.propTypes = {
  id: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(NetworkOperations);
