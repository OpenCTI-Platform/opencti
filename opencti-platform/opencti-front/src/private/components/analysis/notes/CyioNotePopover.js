import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withRouter } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles/index';
import Menu from '@material-ui/core/Menu';
import Typography from '@material-ui/core/Typography';
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
import { QueryRenderer as QR, commitMutation as CM } from 'react-relay';
import inject18n from '../../../../components/i18n';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
// import { QueryRenderer, commitMutation } from '../../../../relay/environment';
// import { noteEditionQuery } from './NoteEdition';
import CyioNoteEditionContainer, { cyioNoteEditionQuery } from './CyioNoteEditionContainer';
import Loader from '../../../../components/Loader';
import Security, {
  KNOWLEDGE_KNUPDATE_KNDELETE,
} from '../../../../utils/Security';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.background.paper,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const CyioNotePopoverDeletionMutation = graphql`
  mutation CyioNotePopoverDeletionMutation($id: ID!) {
    deleteCyioNote(id: $id)
  }
`;

class CyioNotePopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayExport: false,
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

  submitDelete() {
    this.setState({ deleting: true });
    CM(environmentDarkLight, {
      mutation: CyioNotePopoverDeletionMutation,
      variables: {
        id: this.props.id,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleClose();
        if (this.props.handleOpenRemove) {
          this.handleCloseDelete();
        } else {
          this.props.history.push('/dashboard/analysis/notes');
        }
      },
      // onError: (err) => console.log('NoteDeletionDarkLightMutationError', err),
    });
    // commitMutation({
    //   mutation: CyioNotePopoverDeletionMutation,
    //   variables: {
    //     id: this.props.id,
    //   },
    //   updater: (store) => {
    //     if (this.props.entityId) {
    //       const entity = store.get(this.props.entityId);
    //       const conn = ConnectionHandler.getConnection(
    //         entity,
    //         'Pagination_notes',
    //       );
    //       ConnectionHandler.deleteNode(conn, this.props.id);
    //     }
    //   },
    //   onCompleted: () => {
    //     this.setState({ deleting: false });
    //     this.handleClose();
    //     if (this.props.handleOpenRemove) {
    //       this.handleCloseDelete();
    //     } else {
    //       this.props.history.push('/dashboard/analysis/notes');
    //     }
    //   },
    // });
  }

  handleOpenEdit() {
    this.setState({ displayEdit: true });
    this.handleClose();
  }

  handleCloseEdit() {
    this.setState({ displayEdit: false });
  }

  handleOpenRemove(id) {
    this.props.handleOpenRemove(id);
    this.handleClose();
  }

  render() {
    const {
      classes, t, id, handleOpenRemove,
    } = this.props;
    return (
      <div className={classes.container}>
        {/* <IconButton
          aria-haspopup="true"
          style={{ marginTop: 1 }}
        >
          <ExpandMoreOutlined />
        </IconButton> */}
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: -2 }}
        >
          <MoreVert />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
          style={{ marginTop: 50, textAlign: 'center' }}
        >
          <MenuItem
          divider={true}
          className={classes.menuItem}
          onClick={this.handleOpenEdit.bind(this)}>
            {t('Update')}
          </MenuItem>
          {handleOpenRemove && (
            <MenuItem
            divider={true}
            className={classes.menuItem}
            onClick={this.handleOpenRemove.bind(this, id)}>
              {t('Remove')}
            </MenuItem>
          )}
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <MenuItem
            className={classes.menuItem}
            onClick={this.handleOpenDelete.bind(this)}>
              {t('Delete')}
            </MenuItem>
          </Security>
        </Menu>
        <Dialog
          open={this.state.displayDelete}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
            <DialogContent>
              <Typography className={classes.popoverDialog}>
                {t('Are you sure you’d like to delete this item?')}
              </Typography>
              <DialogContentText>
                {t('This action can’t be undone')}
              </DialogContentText>
            </DialogContent>
          <DialogActions className={ classes.dialogActions }>
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
        <Dialog
          open={this.state.displayEdit}
          anchor="right"
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseEdit.bind(this)}
        >
          <QR
            environment={environmentDarkLight}
            query={cyioNoteEditionQuery}
            variables={{ id }}
            render={({ props }) => {
              if (props) {
                return (
                  <CyioNoteEditionContainer
                    note={props.note}
                    handleClose={this.handleCloseEdit.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Dialog>
      </div>
    );
  }
}

CyioNotePopover.propTypes = {
  id: PropTypes.string,
  entityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  handleOpenRemove: PropTypes.func,
};

export default compose(inject18n, withRouter, withStyles(styles))(CyioNotePopover);
