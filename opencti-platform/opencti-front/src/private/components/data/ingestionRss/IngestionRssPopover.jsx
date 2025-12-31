import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
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
import DialogTitle from '@mui/material/DialogTitle';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IngestionRssEdition, { ingestionRssMutationFieldPatch } from './IngestionRssEdition';
import { deleteNode } from '../../../../utils/store';

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

const ingestionRssPopoverDeletionMutation = graphql`
  mutation IngestionRssPopoverDeletionMutation($id: ID!) {
    ingestionRssDelete(id: $id)
  }
`;

const ingestionRssEditionQuery = graphql`
  query IngestionRssPopoverEditionQuery($id: String!) {
    ingestionRss(id: $id) {
      id
      name
      uri
      ingestion_running
      current_state_date
      ...IngestionRssEdition_ingestionRss
    }
  }
`;

class IngestionRssPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
      displayDelete: false,
      deleting: false,
      displayStart: false,
      starting: false,
      displayStop: false,
      stopping: false,
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

  handleOpenDelete() {
    this.setState({ displayDelete: true });
    this.handleClose();
  }

  handleCloseDelete() {
    this.setState({ displayDelete: false });
  }

  handleOpenStart() {
    this.setState({ displayStart: true });
    this.handleClose();
  }

  handleCloseStart() {
    this.setState({ displayStart: false });
  }

  handleOpenStop() {
    this.setState({ displayStop: true });
    this.handleClose();
  }

  handleCloseStop() {
    this.setState({ displayStop: false });
  }

  submitDelete() {
    this.setState({ deleting: true });
    commitMutation({
      mutation: ingestionRssPopoverDeletionMutation,
      variables: {
        id: this.props.ingestionRssId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_ingestionRsss',
          this.props.paginationOptions,
          this.props.ingestionRssId,
        );
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  submitStart() {
    this.setState({ starting: true });
    commitMutation({
      mutation: ingestionRssMutationFieldPatch,
      variables: {
        id: this.props.ingestionRssId,
        input: { key: 'ingestion_running', value: ['true'] },
      },
      onCompleted: () => {
        this.setState({ starting: false });
        this.handleCloseStart();
      },
    });
  }

  submitStop() {
    this.setState({ stopping: true });
    commitMutation({
      mutation: ingestionRssMutationFieldPatch,
      variables: {
        id: this.props.ingestionRssId,
        input: { key: 'ingestion_running', value: ['false'] },
      },
      onCompleted: () => {
        this.setState({ stopping: false });
        this.handleCloseStop();
      },
    });
  }

  render() {
    const { classes, t, ingestionRssId, running } = this.props;
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
          {!running && (
            <MenuItem onClick={this.handleOpenStart.bind(this)}>
              {t('Start')}
            </MenuItem>
          )}
          {running && (
            <MenuItem onClick={this.handleOpenStop.bind(this)}>
              {t('Stop')}
            </MenuItem>
          )}
          <MenuItem onClick={this.handleOpenUpdate.bind(this)}>
            {t('Update')}
          </MenuItem>
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Delete')}
          </MenuItem>
        </Menu>
        <QueryRenderer
          query={ingestionRssEditionQuery}
          variables={{ id: ingestionRssId }}
          render={({ props }) => {
            if (props) {
              return (
                <IngestionRssEdition
                  ingestionRss={props.ingestionRss}
                  handleClose={this.handleCloseUpdate.bind(this)}
                  open={this.state.displayUpdate}
                />
              );
            }
            return <div />;
          }}
        />
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
              {t('Do you want to delete this RSS ingester?')}
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
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayStart}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseStart.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to start this RSS ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseStart.bind(this)}
              disabled={this.state.starting}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitStart.bind(this)}
              disabled={this.state.starting}
            >
              {t('Start')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          slotProps={{ paper: { elevation: 1 } }}
          open={this.state.displayStop}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseStop.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to stop this RSS ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              variant="secondary"
              onClick={this.handleCloseStop.bind(this)}
              disabled={this.state.stopping}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitStop.bind(this)}
              disabled={this.state.stopping}
            >
              {t('Stop')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    );
  }
}

IngestionRssPopover.propTypes = {
  ingestionRssId: PropTypes.string,
  running: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(IngestionRssPopover);
