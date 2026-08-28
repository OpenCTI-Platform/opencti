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
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { deleteNodeFromEdge } from '../../../../utils/store';

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

const indicatorObservablePopoverDeletionMutation = graphql`
  mutation IndicatorObservablePopoverDeletionMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

const IndicatorObservablePopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const handleOpen = (event) => {
    event.stopPropagation();
    event.preventDefault();
    setAnchorEl(event.currentTarget);
  };

  const handleClose = (event) => {
    event.stopPropagation();
    event.preventDefault();
    setAnchorEl(null);
  };

  const handleOpenDelete = (event) => {
    event.stopPropagation();
    event.preventDefault();
    setDisplayDelete(true);
    handleClose(event);
  };

  const handleCloseDelete = (event) => {
    event.stopPropagation();
    event.preventDefault();
    setDeleting(false);
    setDisplayDelete(false);
  };

  const submitDelete = (event) => {
    event.stopPropagation();
    event.preventDefault();
    setDeleting(true);
    commitMutation({
      mutation: indicatorObservablePopoverDeletionMutation,
      variables: {
        fromId: props.indicatorId,
        toId: props.observableId,
        relationship_type: 'based-on',
      },
      updater: (store) => deleteNodeFromEdge(store, 'observables', props.indicatorId, props.observableId, { first: 100 }),
      onCompleted: () => {
        handleCloseDelete(event);
        if (props.onDelete) {
          props.onDelete();
        }
      },
    });
  };

  const { classes } = props;
  return (
    <div className={classes.container}>
      <IconButton
        aria-label={t_i18n('Open menu')}
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Remove')}
        </MenuItem>
      </Menu>
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to remove the observable from this indicator?')}
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

IndicatorObservablePopover.propTypes = {
  indicatorId: PropTypes.string,
  observableId: PropTypes.string,
  secondaryRelationId: PropTypes.string,
  isRelation: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  onDelete: PropTypes.func,
};

export default withStyles(styles)(IndicatorObservablePopover);
