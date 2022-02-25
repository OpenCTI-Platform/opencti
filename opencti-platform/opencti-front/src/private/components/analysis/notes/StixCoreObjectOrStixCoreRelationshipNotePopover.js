import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Drawer from '@mui/material/Drawer';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import { MoreVertOutlined } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import Loader from '../../../../components/Loader';
import NoteEdition from './NoteEdition';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
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

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const stixCoreObjectOrStixCoreRelationshipNotePopoverCleanContext = graphql`
  mutation StixCoreObjectOrStixCoreRelationshipNotePopoverCleanContextMutation(
    $id: ID!
  ) {
    noteEdit(id: $id) {
      contextClean {
        ...NoteEditionOverview_note
      }
    }
  }
`;

const stixCoreObjectOrStixCoreRelationshipNotePopoverDeletionMutation = graphql`
  mutation StixCoreObjectOrStixCoreRelationshipNotePopoverDeletionMutation(
    $id: ID!
  ) {
    noteEdit(id: $id) {
      delete
    }
  }
`;

const stixCoreObjectOrStixCoreRelationshipNotePopoverEditionQuery = graphql`
  query StixCoreObjectOrStixCoreRelationshipNotePopoverEditionQuery(
    $id: String!
  ) {
    note(id: $id) {
      ...NoteEditionOverview_note
    }
  }
`;

class StixCoreObjectOrStixCoreRelationshipNotePopover extends Component {
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
    commitMutation({
      mutation: stixCoreObjectOrStixCoreRelationshipNotePopoverCleanContext,
      variables: { id: this.props.roleId },
    });
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
      mutation: stixCoreObjectOrStixCoreRelationshipNotePopoverDeletionMutation,
      variables: {
        id: this.props.noteId,
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
        this.props.onUpdate();
      },
    });
  }

  render() {
    const { classes, t, noteId } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
        >
          <MoreVertOutlined />
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
        <Drawer
          open={this.state.displayUpdate}
          anchor="right"
          elevation={1}
          sx={{ zIndex: 1202 }}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseUpdate.bind(this)}
        >
          <QueryRenderer
            query={stixCoreObjectOrStixCoreRelationshipNotePopoverEditionQuery}
            variables={{ id: noteId }}
            render={({ props }) => {
              if (props) {
                return (
                  <NoteEdition
                    note={props.note}
                    handleClose={this.handleCloseUpdate.bind(this)}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Drawer>
        <Dialog
          open={this.state.displayDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this note?')}
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

StixCoreObjectOrStixCoreRelationshipNotePopover.propTypes = {
  noteId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onUpdate: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectOrStixCoreRelationshipNotePopover);
