import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import DialogTitle from '@mui/material/DialogTitle';
import inject18n from '../../../../../components/i18n';
import { APP_BASE_PATH, commitMutation } from '../../../../../relay/environment';
import { resolveLink } from '../../../../../utils/Entity';
import withRouter from '../../../../../utils/compat_router/withRouter';

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

const workbenchFilePopoverDeleteMutation = graphql`
  mutation WorkbenchFilePopoverDeleteMutation($fileName: String) {
    deleteImport(fileName: $fileName)
  }
`;

class WorkbenchFilePopover extends Component {
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
    const { file } = this.props;
    commitMutation({
      mutation: workbenchFilePopoverDeleteMutation,
      variables: { fileName: file.id },
      onCompleted: () => {
        if (this.props.file.metaData.entity) {
          const entityLink = `${resolveLink(
            this.props.file.metaData.entity.entity_type,
          )}/${this.props.file.metaData.entity.id}`;
          this.props.navigate(`${entityLink}/files`);
        } else {
          this.props.navigate('/dashboard/data/import');
        }
      },
    });
  }

  render() {
    const { classes, t, file } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          color="primary"
        >
          <MoreVert />
        </IconButton>
        <Menu
          anchorEl={this.state.anchorEl}
          open={Boolean(this.state.anchorEl)}
          onClose={this.handleClose.bind(this)}
        >
          <MenuItem
            component="a"
            href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(file.id)}`}
          >
            {t('Download')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayDelete}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this workbench?')}
            </DialogContentText>
          </DialogContent>
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

WorkbenchFilePopover.propTypes = {
  file: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  navigate: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(WorkbenchFilePopover);
