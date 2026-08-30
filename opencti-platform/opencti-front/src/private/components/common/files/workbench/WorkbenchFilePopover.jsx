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
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../../components/i18n';
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

const WorkbenchFilePopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };

  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

  const submitDelete = () => {
    setDeleting(true);
    const { file } = props;
    commitMutation({
      mutation: workbenchFilePopoverDeleteMutation,
      variables: { fileName: file.id },
      onCompleted: () => {
        if (props.file.metaData.entity) {
          const entityLink = `${resolveLink(
            props.file.metaData.entity.entity_type,
          )}/${props.file.metaData.entity.id}`;
          props.navigate(`${entityLink}/files`);
        } else {
          props.navigate('/dashboard/data/import');
        }
      },
    });
  };

  const { classes, file } = props;
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-label={t_i18n('Open menu')}
        aria-haspopup="true"
        size="default"
        variant="secondary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem
          component="a"
          href={`${APP_BASE_PATH}/storage/get/${encodeURIComponent(file.id)}`}
        >
          {t_i18n('Download')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this workbench?')}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={handleCloseDelete}
            disabled={deleting}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={submitDelete}
            disabled={deleting}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

WorkbenchFilePopover.propTypes = {
  file: PropTypes.object,
  classes: PropTypes.object,
  navigate: PropTypes.func,
};

export default compose(
  withRouter,
  withStyles(styles),
)(WorkbenchFilePopover);
