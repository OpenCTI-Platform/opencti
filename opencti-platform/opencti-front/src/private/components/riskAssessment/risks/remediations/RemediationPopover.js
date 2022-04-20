import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import { QueryRenderer as QR } from 'react-relay';
import MenuItem from '@material-ui/core/MenuItem';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../../components/i18n';
import QueryRendererDarkLight from '../../../../../relay/environmentDarkLight';
import { commitMutation } from '../../../../../relay/environment';
// import StixCoreRelationshipEdition from './StixCoreRelationshipEdition';
import RemediationDetailsPopover from './RemediationDetailsPopover';

const styles = (theme) => ({
  container: {
    margin: 0,
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
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const remediationPopoverDeletionMutation = graphql`
  mutation RemediationPopoverDeletionMutation($id: ID!) {
    stixCoreRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const remediationPopoverQuery = graphql`
  query RemediationPopoverQuery($id: ID!) {
    riskResponse(id: $id) {
      id
      name                # Title
      description         # Description
      created             # Created
      modified            # Last Modified
      lifecycle           # Lifecycle
      response_type       # Response Type
      origins{            # Detection Source
        id
        origin_actors {
          actor_type
          actor_ref {
            ... on Component {
              id
              component_type
              name          # Source
            }
            ... on OscalParty {
              id
              party_type
              name            # Source
            }
          }
        }
      }
    }
  }
`;

class RemediationPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      displayEdit: false,
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

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
    this.handleClose();
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
      mutation: remediationPopoverDeletionMutation,
      variables: {
        id: this.props.cyioCoreRelationshipId,
      },
      updater: (store) => {
        if (typeof this.props.onDelete !== 'function') {
          const container = store.getRoot();
          const payload = store.getRootField('stixCoreRelationshipEdit');
          const userProxy = store.get(container.getDataID());
          const conn = ConnectionHandler.getConnection(
            userProxy,
            this.props.connectionKey || 'Pagination_stixCoreRelationships',
            this.props.paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
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
    const {
      classes, t, cyioCoreRelationshipId, disabled, history, riskId,
    } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          disabled={disabled}
        >
          <MoreVertOutlined />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50 }}
        >
          {/* <MenuItem
            className={classes.menuItem}
            divider={true}
            onClick={this.handleOpenEdit.bind(this)}
          >
            {t('Update')}
          </MenuItem> */}
          <MenuItem
            className={classes.menuItem}
            onClick={this.handleDisplayEdit.bind(this)}
          >
            {t('Edit Remediation')}
          </MenuItem>
          {/* <MenuItem
            className={classes.menuItem}
            divider={true}
            onClick={this.handleOpenDelete.bind(this)}
          >
            {t('Delete')}
          </MenuItem> */}
        </Menu>
        {/* <StixCoreRelationshipEdition
          variant="noGraph"
          cyioCoreRelationshipId={cyioCoreRelationshipId}
          open={this.state.displayUpdate}
          handleClose={this.handleCloseUpdate.bind(this)}
        /> */}
        <Dialog
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <Typography className={classes.popoverDialog} >
              {t('Are you sure you’d like to delete this item?')}
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
        <QR
          environment={QueryRendererDarkLight}
          query={remediationPopoverQuery}
          variables={{ id: cyioCoreRelationshipId }}
          render={({ error, props, retry }) => {
            if (props) {
              return (
                <RemediationDetailsPopover
                  displayEdit={this.state.displayEdit}
                  history={history}
                  handleDisplayEdit={this.handleDisplayEdit.bind(this)}
                  remediation={props.riskResponse}
                  riskId={riskId}
                />
              );
            }
            return <></>;
          }}
        />
      </div>
    );
  }
}

RemediationPopover.propTypes = {
  cyioCoreRelationshipId: PropTypes.string,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  onDelete: PropTypes.func,
  connectionKey: PropTypes.string,
  riskId: PropTypes.string,
};

export default compose(
  inject18n,
  withStyles(styles),
)(RemediationPopover);
