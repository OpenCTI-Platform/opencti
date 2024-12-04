import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import Slide from '@mui/material/Slide';
import MoreVert from '@mui/icons-material/MoreVert';
import inject18n from '../../../../components/i18n';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import IngestionTaxiiEdition, { ingestionTaxiiMutationFieldPatch } from './IngestionTaxiiEdition';
import { deleteNode } from '../../../../utils/store';

const styles = () => ({
  container: {
    margin: 0,
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const ingestionTaxiiPopoverDeletionMutation = graphql`
  mutation IngestionTaxiiPopoverDeletionMutation($id: ID!) {
    ingestionTaxiiDelete(id: $id)
  }
`;

const ingestionTaxiiPopoverResetStateMutation = graphql`
    mutation IngestionTaxiiPopoverResetStateMutation($id: ID!) {
        ingestionTaxiiResetState(id: $id) {
            id
        }
    }
`;

const ingestionTaxiiEditionQuery = graphql`
  query IngestionTaxiiPopoverEditionQuery($id: String!) {
    ingestionTaxii(id: $id) {
      id
      name
      description
      uri
      version
      ingestion_running
      ...IngestionTaxiiEdition_ingestionTaxii
    }
  }
`;

class IngestionTaxiiPopover extends Component {
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
      displayResetState: false,
      resetingState: false,
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

  handleOpenResetState() {
    this.setState({ displayResetState: true });
    this.handleClose();
  }

  handleCloseResetState() {
    this.setState({ displayResetState: false });
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
      mutation: ingestionTaxiiPopoverDeletionMutation,
      variables: {
        id: this.props.ingestionTaxiiId,
      },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_ingestionTaxiis',
          this.props.paginationOptions,
          this.props.ingestionTaxiiId,
        );
      },
      onCompleted: () => {
        this.setState({ deleting: false });
        this.handleCloseDelete();
      },
    });
  }

  submitResetState() {
    this.setState({ resetingState: true });
    commitMutation({
      mutation: ingestionTaxiiPopoverResetStateMutation,
      variables: {
        id: this.props.ingestionTaxiiId,
      },
      onCompleted: () => {
        this.setState({ resetingState: false });
        this.handleCloseResetState();
      },
    });
  }

  submitStart() {
    this.setState({ starting: true });
    commitMutation({
      mutation: ingestionTaxiiMutationFieldPatch,
      variables: {
        id: this.props.ingestionTaxiiId,
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
      mutation: ingestionTaxiiMutationFieldPatch,
      variables: {
        id: this.props.ingestionTaxiiId,
        input: { key: 'ingestion_running', value: ['false'] },
      },
      onCompleted: () => {
        this.setState({ stopping: false });
        this.handleCloseStop();
      },
    });
  }

  render() {
    const { classes, t, ingestionTaxiiId, running } = this.props;
    return (
      <div className={classes.container}>
        <IconButton
          onClick={this.handleOpen.bind(this)}
          aria-haspopup="true"
          style={{ marginTop: 3 }}
          size="large"
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
          <MenuItem onClick={this.handleOpenResetState.bind(this)}>
            {t('Reset state')}
          </MenuItem>
        </Menu>
        <QueryRenderer
          query={ingestionTaxiiEditionQuery}
          variables={{ id: ingestionTaxiiId }}
          render={({ props }) => {
            if (props) {
              return (
                <IngestionTaxiiEdition
                  ingestionTaxii={props.ingestionTaxii}
                  handleClose={this.handleCloseUpdate.bind(this)}
                  open={this.state.displayUpdate}
                />
              );
            }
            return <div />;
          }}
        />
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayDelete}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to delete this TAXII ingester?')}
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
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayResetState}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseResetState.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to reset the state of this TAXII ingester? It will restart ingestion from the beginning.')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseResetState.bind(this)}
              disabled={this.state.resetingState}
            >
              {t('Cancel')}
            </Button>
            <Button
              color="secondary"
              onClick={this.submitResetState.bind(this)}
              disabled={this.state.resetingState}
            >
              {t('Reset state')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayStart}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseStart.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to start this TAXII ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseStart.bind(this)}
              disabled={this.state.starting}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitStart.bind(this)}
              color="secondary"
              disabled={this.state.starting}
            >
              {t('Start')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          PaperProps={{ elevation: 1 }}
          open={this.state.displayStop}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={this.handleCloseStop.bind(this)}
        >
          <DialogContent>
            <DialogContentText>
              {t('Do you want to stop this TAXII ingester?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button
              onClick={this.handleCloseStop.bind(this)}
              disabled={this.state.stopping}
            >
              {t('Cancel')}
            </Button>
            <Button
              onClick={this.submitStop.bind(this)}
              color="secondary"
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

IngestionTaxiiPopover.propTypes = {
  ingestionTaxiiId: PropTypes.string,
  running: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(IngestionTaxiiPopover);
