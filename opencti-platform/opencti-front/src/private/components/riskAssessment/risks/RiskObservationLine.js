import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import Divider from '@material-ui/core/Divider';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogContent from '@material-ui/core/DialogContent';
import MoreVertOutlined from '@material-ui/icons/MoreVertOutlined';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import { toastGenericError } from '../../../../utils/bakedToast';
import RiskObservationPopover, { riskObservationPopoverQuery } from './RiskObservationPopover';
import { QueryRenderer } from '../../../../relay/environment';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    padding: 0,
    position: 'relative',
  },
  drawerPaper: {
    margin: '0px',
    height: '900px',
    overflow: 'hidden',
    position: 'fixed',
    padding: '15px 20px',
  },
  dialogContent: {
    overflow: 'hidden',
    padding: '50px 0',
  },
  observationList: {
    marginBottom: 0,
    padding: '0 12px 12px 12px',
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
  observationMain: {
    display: 'grid',
    gridTemplateColumns: '90% 10%',
    marginBottom: '10px',
  },

});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RiskObservationLineContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayDialog: false,
      displayExternalLink: false,
      externalLink: null,
      removeExternalReference: null,
      removing: false,
      displayExternalRefID: false,
      expanded: false,
      observationId: '',
      displayDetails: false,
    };
  }

  handleOpen(event) {
    this.setState({ anchorEl: event.currentTarget });
  }

  handleClose() {
    this.setState({ anchorEl: null });
  }

  handleOpenUpdate(observationNewId) {
    this.setState({ displayDetails: true, observationId: observationNewId });
  }

  handleCloseUpdate() {
    this.setState({ displayDetails: false, observationId: '' });
    this.handleClose();
  }

  handleToggleExpand() {
    this.setState({ expanded: !this.state.expanded });
  }

  handleOpenDialog(externalReferenceEdge) {
    const openedState = {
      displayDialog: true,
      removeExternalReference: externalReferenceEdge,
    };
    this.setState(openedState);
  }

  handleCloseDialog() {
    const closedState = {
      displayDialog: false,
      removeExternalReference: null,
    };
    this.setState(closedState);
  }

  handleRemoval() {
    this.setState({ removing: true });
    this.removeExternalReference(this.state.removeExternalReference);
  }

  handleOpenExternalLink(url) {
    this.setState({ displayExternalLink: true, externalLink: url });
  }

  handleCloseExternalLink() {
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleBrowseExternalLink() {
    window.open(this.state.externalLink, '_blank');
    this.setState({ displayExternalLink: false, externalLink: null });
  }

  handleToggleDetails() {
    this.setState({ displayExternalRefID: !this.state.displayExternalRefID });
  }

  render() {
    const {
      t, classes, fldt, observation, observationId, history,
    } = this.props;
    return (
      <>
        <div>
          <List key={observation.node.id} className={classes.observationList}>
            <div>
              <div className={classes.observationMain}>
                <div style={{ padding: '10px 0 0 18px' }}>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <Typography
                      variant="h2"
                      color="textSecondary"
                      style={{ textTransform: 'capitalize', paddingRight: '7px' }}
                    >
                      {t('Observed on')}
                    </Typography>
                    <Typography
                      variant="h3"
                    >
                      <strong style={{ color: 'white' }}>
                        {observation.node.collected && fldt(observation.node.collected)}
                      </strong>
                    </Typography>
                  </div>
                  <div className="clearfix" />
                  <Typography
                    variant="h3"
                    style={{ color: 'white' }}
                  >
                    {observation.node.name && t(observation.node.name)}
                  </Typography>
                </div>
                <div style={{ marginTop: '12px' }}>
                  <IconButton
                    onClick={this.handleOpen.bind(this)}
                    aria-haspopup="true"
                    style={{ marginTop: 1 }}
                  >
                    <MoreVertOutlined />
                  </IconButton>
                  <Menu
                    anchorEl={this.state.anchorEl}
                    open={Boolean(this.state.anchorEl)}
                    onClose={this.handleClose.bind(this)}
                    style={{ marginTop: 50 }}
                  >
                    <MenuItem
                      className={classes.menuItem}
                      // onClick={this.handleOpenUpdate.bind(this)}
                      onClick={this.handleOpenUpdate.bind(this, observationId)}
                    >
                      {t('Details')}
                    </MenuItem>
                  </Menu>
                </div>
              </div>
              <Divider variant="middle" light={true} />
            </div>
          </List>
        </div>
        {this.state.observationId && (
          <Dialog
            open={this.state.displayDetails}
            keepMounted={true}
            classes={{ paper: classes.drawerPaper }}
          >
            <QueryRenderer
              query={riskObservationPopoverQuery}
              variables={{ id: this.state.observationId }}
              render={({ error, props }) => {
                if (error) {
                  return (
                    toastGenericError('Failed to get risk observation Details')
                  );
                }
                if (props) {
                  return (
                    <RiskObservationPopover
                      handleCloseUpdate={this.handleCloseUpdate.bind(this)}
                      displayUpdate={this.state.displayDetails}
                      data={props.observation}
                      history={history}
                    />
                  );
                }
                return (
                  <DialogContent classes={{ root: classes.dialogContent }}>
                    <Loader />
                  </DialogContent>
                );
              }
              }
            />
          </Dialog>
        )}
      </>
    );
  }
}

RiskObservationLineContainer.propTypes = {
  observationId: PropTypes.string,
  observation: PropTypes.object,
  risk: PropTypes.object,
  cyioCoreObjectId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
  fd: PropTypes.func,
  relay: PropTypes.object,
  history: PropTypes.object,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(RiskObservationLineContainer);
