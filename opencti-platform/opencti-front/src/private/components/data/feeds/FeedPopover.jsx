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
import { ConnectionHandler } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import FeedCreation from './FeedCreation';
import FeedEdition from './FeedEdition';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const feedPopoverDeletionMutation = graphql`
  mutation FeedPopoverDeletionMutation($id: ID!) {
    feedDelete(id: $id)
  }
`;

const feedEditionQuery = graphql`
  query FeedPopoverEditionQuery($id: String!) {
    feed(id: $id) {
      id
      name
      ...FeedEdition_feed
    }
  }
`;

const feedDuplicateQuery = graphql`
  query FeedPopoverDuplicateQuery($id: String!) {
    feed(id: $id) {
      id
      name
      ...FeedCreation
    }
  }
`;

const FeedPopover = (props) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleOpenDuplicate = () => {
    setDisplayDuplicate(true);
    handleClose();
  };

  const handleCloseDuplicate = () => {
    setDisplayDuplicate(false);
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
    commitMutation({
      mutation: feedPopoverDeletionMutation,
      variables: {
        id: props.feedId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_feeds',
          props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, props.feedId);
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  const { classes, feedId } = props;
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-label={t_i18n('Open menu')}
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
        <MenuItem onClick={handleOpenUpdate}>
          {t_i18n('Update')}
        </MenuItem>
        <MenuItem onClick={handleOpenDuplicate}>
          {t_i18n('Duplicate')}
        </MenuItem>
        <MenuItem onClick={handleOpenDelete}>
          {t_i18n('Delete')}
        </MenuItem>
      </Menu>
      <QueryRenderer
        query={feedEditionQuery}
        variables={{ id: feedId }}
        render={({ props }) => {
          if (props) {
            return (
              <>
                <FeedEdition
                  feed={props.feed}
                  handleClose={handleCloseUpdate}
                  open={displayUpdate}
                />
              </>
            );
          }
          return <div />;
        }}
      />
      <QueryRenderer
        query={feedDuplicateQuery}
        variables={{ id: feedId }}
        render={({ props }) => {
          if (props) {
            return (
              <FeedCreation
                feed={props.feed}
                onDrawerClose={handleCloseDuplicate}
                open={displayDuplicate}
                paginationOptions={props.paginationOptions}
                isDuplicated={true}
              />
            );
          }
          return <div />;
        }}
      />
      <Dialog
        open={displayDelete}
        onClose={handleCloseDelete}
        size="small"
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {t_i18n('Do you want to delete this feed?')}
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

FeedPopover.propTypes = {
  feedId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
};

export default compose(withStyles(styles))(FeedPopover);
