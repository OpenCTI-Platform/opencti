import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { MoreVertOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Slide from '@mui/material/Slide';
import withStyles from '@mui/styles/withStyles';
import * as PropTypes from 'prop-types';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import stopEvent from '../../../../utils/domEvent';
import StixNestedRefRelationshipEdition from './StixNestedRefRelationshipEdition';

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

const stixNestedRefRelationshipPopoverDeletionMutation = graphql`
  mutation StixNestedRefRelationshipPopoverDeletionMutation($id: ID!) {
    stixRefRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const StixNestedRefRelationshipPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };

  const handleClose = (event) => {
    setAnchorEl(null);
    stopEvent(event);
  };

  const handleOpenUpdate = (event) => {
    setDisplayUpdate(true);
    handleClose(event);
  };

  const handleCloseUpdate = (event) => {
    setDisplayUpdate(false);
    stopEvent(event);
  };

  const handleOpenDelete = (event) => {
    setDisplayDelete(true);
    handleClose(event);
  };

  const handleCloseDelete = (event) => {
    setDisplayDelete(false);
    stopEvent(event);
  };

  const submitDelete = (event) => {
    setDeleting(true);
    stopEvent(event);
    commitMutation({
      mutation: stixNestedRefRelationshipPopoverDeletionMutation,
      variables: {
        id: props.stixNestedRefRelationshipId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const payload = store.getRootField(
          'stixRefRelationshipEdit',
        );
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_stixNestedRefRelationships',
          props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, payload.getValue('delete'));
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete(event);
      },
    });
  };

  const { classes, stixNestedRefRelationshipId, disabled } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        onClick={handleOpen}
        aria-haspopup="true"
        disabled={disabled}
        color="primary"
      >
        <MoreVertOutlined />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <StixNestedRefRelationshipEdition
        variant="noGraph"
        stixNestedRefRelationshipId={stixNestedRefRelationshipId}
        open={displayUpdate}
        handleClose={handleCloseUpdate}
      />
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this relation?')}
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

StixNestedRefRelationshipPopover.propTypes = {
  stixNestedRefRelationshipId: PropTypes.string,
  disabled: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
};

export default withStyles(styles)(StixNestedRefRelationshipPopover);
