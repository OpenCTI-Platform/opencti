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

class IndicatorObservablePopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayDelete: false,
      deleting: false,
    };
  }

  handleOpen(event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose(event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ anchorEl: null });
  }

  handleOpenDelete(event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ displayDelete: true });
    this.handleClose(event);
  }

  handleCloseDelete(event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ deleting: false, displayDelete: false });
  }

  submitDelete(event) {
    event.stopPropagation();
    event.preventDefault();
    this.setState({ deleting: true });
    commitMutation({
      mutation: indicatorObservablePopoverDeletionMutation,
      variables: {
        fromId: this.props.indicatorId,
        toId: this.props.observableId,
        relationship_type: 'based-on',
      },
      updater: (store) => deleteNodeFromEdge(store, 'observables', this.props.indicatorId, this.props.observableId, { first: 100 }),
      onCompleted: () => {
        this.handleCloseDelete(event);
        if (this.props.onDelete) {
          this.props.onDelete();
        }
      },
    });
  }

  render() {
    const { classes, t } = this.props;
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
          <MenuItem onClick={this.handleOpenDelete.bind(this)}>
            {t('Remove')}
          </MenuItem>
        </Menu>
        <Dialog
          open={this.state.displayDelete}
          slotProps={{ paper: { elevation: 1 } }}
          keepMounted={true}
          slots={{ transition: Transition }}
          onClose={this.handleCloseDelete.bind(this)}
        >
          <DialogTitle>
            {t('Are you sure?')}
          </DialogTitle>
          <DialogContent>
            <DialogContentText>
              {t('Do you want to remove the observable from this indicator?')}
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

IndicatorObservablePopover.propTypes = {
  indicatorId: PropTypes.string,
  observableId: PropTypes.string,
  secondaryRelationId: PropTypes.string,
  isRelation: PropTypes.bool,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onDelete: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(IndicatorObservablePopover);
