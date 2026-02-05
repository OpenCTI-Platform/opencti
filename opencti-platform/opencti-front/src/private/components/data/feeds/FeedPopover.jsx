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
import React, { Component } from 'react';
import { graphql } from 'react-relay';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../../components/i18n';
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

class FeedPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      displayDuplicate: false,
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
    this.setState({ displayUpdate: false });
  }

  handleOpenDuplicate() {
    this.setState({ displayDuplicate: true });
    this.handleClose();
  }

  handleCloseDuplicate() {
    this.setState({ displayDuplicate: false });
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
      mutation: feedPopoverDeletionMutation,
      variables: {
        id: this.props.feedId,
      },
      updater: (store) => {
        const container = store.getRoot();
        const userProxy = store.get(container.getDataID());
        const conn = ConnectionHandler.getConnection(
          userProxy,
          'Pagination_feeds',
          this.props.paginationOptions,
        );
        ConnectionHandler.deleteNode(conn, this.props.feedId);
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  render() {
    const { classes, t, feedId } = this.props;
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
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDuplicate.bind(this)}>
            {t('Duplicate')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
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
                    handleClose={this.handleCloseUpdate.bind(this)}
                    open={this.state.displayUpdate}
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
                  onDrawerClose={this.handleCloseDuplicate.bind(this)}
                  open={this.state.displayDuplicate}
                  paginationOptions={this.props.paginationOptions}
                  isDuplicated={true}
                />
              );
            }
            return <div />;
          }}
        />
        <Dialog
          open={this.state.displayDelete}
          onClose={this.handleCloseDelete.bind(this)}
          size="small"
          title={t('Are you sure?')}
        >
          <DialogContentText>
            {t('Do you want to delete this feed?')}
          </DialogContentText>
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

FeedPopover.propTypes = {
  feedId: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(FeedPopover);
