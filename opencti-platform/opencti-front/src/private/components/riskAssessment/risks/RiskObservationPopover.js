import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
// import { ConnectionHandler } from 'relay-runtime';
import { withStyles } from '@material-ui/core/styles/index';
import Typography from '@material-ui/core/Typography';
import Menu from '@material-ui/core/Menu';
import MenuItem from '@material-ui/core/MenuItem';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
// import ManageSearchIcon from '@material-ui/icons/m';
import AccessTimeIcon from '@material-ui/icons/AccessTime';
import LaunchIcon from '@material-ui/icons/Launch';
import FindInPageIcon from '@material-ui/icons/FindInPage';
import LayersIcon from '@material-ui/icons/Layers';
import MapIcon from '@material-ui/icons/Map';
import Divider from '@material-ui/core/Divider';
import IconButton from '@material-ui/core/IconButton';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import { MoreVertOutlined } from '@material-ui/icons';
import environmentDarkLight from '../../../../relay/environmentDarkLight';
import inject18n from '../../../../components/i18n';
// import { commitMutation, QueryRenderer } from '../../../../relay/environment';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  drawerPaper: {
    width: '50%',
    position: 'fixed',
    overflow: 'auto',
    backgroundColor: theme.palette.background.paper,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: '15px 20px',
  },
  menuItem: {
    padding: '15px 0',
    width: '152px',
    margin: '0 20px',
    justifyContent: 'center',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  popoverDialog: {
    fontSize: '18px',
    lineHeight: '24px',
    color: theme.palette.header.text,
  },
  observationHeading: {
    display: 'flex',
    alignItems: 'center',
    textTransform: 'uppercase',
  },
  statusButton: {
    cursor: 'default',
    background: '#075AD333',
    marginBottom: '5px',
    border: '1px solid #075AD3',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class RiskObservationPopover extends Component {
  constructor(props) {
    super(props);
    this.state = {
      anchorEl: null,
      displayUpdate: false,
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

  render() {
    const {
      classes,
      t,
      fd,
      data,
      handleRemove,
    } = this.props;
    return (
      <>
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
            onClick={this.handleOpenUpdate.bind(this)}>
            {t('Details')}
          </MenuItem>
        </Menu>
        <Dialog
          open={this.state.displayUpdate}
          keepMounted={true}
          classes={{ paper: classes.drawerPaper }}
          onClose={this.handleCloseUpdate.bind(this)}
        >
          <DialogContent>
            <DialogContentText style={{ color: 'white' }}>
              {data.name && t(data.name)}
            </DialogContentText>
            <DialogContentText>
              <Grid style={{ margin: '25px 0' }} container={true} xs={12}>
                <Grid item={true} xs={3}>
                  <Typography className={classes.observationHeading} color="textSecondary" variant="h3" >
                    <FindInPageIcon fontSize="small" style={{ marginRight: '8px' }} />How
                  </Typography>
                </Grid>
                <Grid item={true} xs={9}>
                  <DialogContentText>
                    {t('Source Of Observation')}
                  </DialogContentText>
                  <Typography style={{ alignItems: 'center', display: 'flex' }} color="primary">
                    {data.origins.map((origin, i) => {
                      const originActor = R.pipe(
                        R.pathOr([], ['origin_actors']),
                        R.mergeAll,
                      )(origin);
                      return (
                        <>
                          <LaunchIcon key={i} fontSize='small' /> {t(originActor.actor_ref.name)}
                        </>
                      );
                    })}
                  </Typography>
                  <Grid style={{ marginTop: '20px' }} spacing={3} container={true}>
                    <Grid item={true} xs={6}>
                      <DialogContentText>
                        {t('Methods')}
                      </DialogContentText>
                      {data.methods.map((value, i) => (
                        <Button
                          variant="outlined"
                          size="small"
                          key={i}
                          style={{ margin: '1px' }}
                          className={classes.statusButton}
                        >
                          {value}
                        </Button>
                      ))}
                      <Typography style={{ marginTop: '5px', textTransform: 'inherit' }} variant="h4">
                        {t('A manual or automated test was performed.')}
                      </Typography>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <DialogContentText>
                        {t('Type')}
                      </DialogContentText>
                      {data.observation_types.map((value, i) => (
                        <Button
                          variant="outlined"
                          size="small"
                          key={i}
                          style={{ margin: '1px' }}
                          className={classes.statusButton}
                        >
                          {value}
                        </Button>
                      ))}
                      <Typography style={{ marginTop: '5px', textTransform: 'inherit' }} variant="h4">
                        {t(' An assessment finding made by a source.')}
                      </Typography>
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
              <Divider />
            </DialogContentText>

            <DialogContentText>
              <Grid style={{ margin: '25px 0' }} container={true} xs={12}>
                <Grid item={true} xs={3}>
                  <Typography className={classes.observationHeading} color="textSecondary" variant="h3" >
                    <AccessTimeIcon fontSize="small" style={{ marginRight: '8px' }} /> When
                  </Typography>
                </Grid>
                <Grid item={true} xs={9}>
                  <Grid container={true}>
                    <Grid item={true} xs={6}>
                      <DialogContentText>
                        {t('Collected')}
                      </DialogContentText>
                      <Typography variang="h2" style={{ color: 'white' }}>
                        {data.collected && fd(data.collected)}
                      </Typography>
                    </Grid>
                    <Grid item={true} xs={6}>
                      <DialogContentText>
                        {t('Expiration Date')}
                      </DialogContentText>
                      <Typography variang="h2" style={{ color: 'white' }}>
                        {data.expires && fd(data.expires)}
                      </Typography>
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
              <Divider />
            </DialogContentText>

            <DialogContentText>
              <Grid style={{ margin: '25px 0' }} container={true} xs={12}>
                <Grid item={true} xs={3}>
                  <Typography className={classes.observationHeading} color="textSecondary" variant="h3" >
                    <MapIcon fontSize="small" style={{ marginRight: '8px' }} />Where
                  </Typography>
                </Grid>
                <Grid item={true} xs={9}>
                  <DialogContentText>
                    {t('Observation Target(s)')}
                  </DialogContentText>
                  {data.subjects && data.subjects.map((subject, i) => {
                    if (subject && subject.subject_context === 'target') {
                      return (
                        <Typography key={i} variant="h2" color="primary">
                          {subject.subject_ref && t(subject.subject_ref.name)}
                        </Typography>
                      );
                    }
                    return <></>;
                  })}
                </Grid>
              </Grid>
              <Divider />
            </DialogContentText>

            <DialogContentText>
              <Grid style={{ margin: '25px 0' }} container={true} xs={12}>
                <Grid item={true} xs={3}>
                  <Typography className={classes.observationHeading} color="textSecondary" variant="h3" >
                    <LayersIcon fontSize="small" style={{ marginRight: '8px' }} />What
                  </Typography>
                </Grid>
                <Grid item={true} xs={9}>
                  <DialogContentText>
                    {t('Component(s)')}
                  </DialogContentText>
                  {data.subjects && data.subjects.map((subject, i) => {
                    if (subject && subject.subject_context === 'secondary_target') {
                      return (
                        <Typography key={i} variant="h2" color="primary">
                          {subject.subject_ref && t(subject.subject_ref.name)}
                        </Typography>
                      );
                    }
                    return <></>;
                  })}
                </Grid>
              </Grid>
              <Divider />
            </DialogContentText>
          </DialogContent>
          <DialogActions style={{ marginLeft: '15px', display: 'flex', justifyContent: 'flex-start' }}>
            <Button
              onClick={this.handleCloseUpdate.bind(this)}
              variant="outlined"
            >
              {t('Close')}
            </Button>
          </DialogActions>
        </Dialog>
      </>
    );
  }
}

RiskObservationPopover.propTypes = {
  data: PropTypes.object,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  handleRemove: PropTypes.func,
};

export const RiskObservationPopoverComponent = createFragmentContainer(RiskObservationPopover, {
  data: graphql`
    fragment RiskObservationPopover_risk on Observation {
      id
      entity_type
      name
      description
      methods
      observation_types
      collected
      origins {
        origin_actors {
          # actor_type
          actor_ref {
            ... on AssessmentPlatform {
              id
              name
            }
            ... on Component {
              id
              component_type
              name
            }
            ... on OscalParty {
              id
              party_type
              name
            }
          }
        }
      }
      subjects {
        id
        entity_type
        name
        subject_context
        subject_type
        subject_ref {
          ... on Component {
            id
            entity_type
            name
          }
          ... on InventoryItem {
            id
            entity_type
            name
          }
          ... on OscalLocation {
            id
            entity_type
            name
          }
          ... on OscalParty {
            id
            entity_type
            name
          }
          ... on OscalUser {
            id
            entity_type
            name
          }
        }
      }
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(RiskObservationPopoverComponent);
