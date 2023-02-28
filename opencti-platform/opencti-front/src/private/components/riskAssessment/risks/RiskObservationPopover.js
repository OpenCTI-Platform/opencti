import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles/index';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';
import Grid from '@material-ui/core/Grid';
import { Link } from '@material-ui/core';
import AccessTimeIcon from '@material-ui/icons/AccessTime';
import LaunchIcon from '@material-ui/icons/Launch';
import FindInPageIcon from '@material-ui/icons/FindInPage';
import LayersIcon from '@material-ui/icons/Layers';
import MapIcon from '@material-ui/icons/Map';
import Divider from '@material-ui/core/Divider';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import DialogTitle from '@material-ui/core/DialogTitle';
import DialogContentText from '@material-ui/core/DialogContentText';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
  container: {
    margin: 0,
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
  dialogContent: {
    overflowY: 'hidden',
    '@media (max-height: 1000px)': {
      overflowY: 'scroll',
    },
  },
  link: {
    textAlign: 'left',
    fontSize: '16px',
    font: 'DIN Next LT Pro',
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
  componentScroll: {
    height: '80px',
    overflowY: 'scroll',
  },
  observationContainer: {
    color: theme.palette.primary.text,
    display: 'flex',
    alignItems: 'center',
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

  render() {
    const {
      classes,
      t,
      fd,
      data,
      handleCloseUpdate,
      history,
    } = this.props;
    // const subjectTypes = R.pipe(
    //   R.pathOr([], ['subjects']),
    //   // R.mergeAll,
    // )(data);
    return (
      <>
        <DialogTitle style={{ color: 'white' }}>
          {data.name && t(data.name)}
        </DialogTitle>
        <DialogContent classes={{ root: classes.dialogContent }}>
          <DialogContentText>
            <Grid style={{ margin: '25px 0' }} container={true} xs={12}>
              <Grid item={true} xs={3}>
                <Typography className={classes.observationHeading} color="textSecondary" variant="h3" >
                  <FindInPageIcon fontSize="small" style={{ marginRight: '8px' }} />How
                </Typography>
              </Grid>
              <Grid item={true} xs={9}>
                <DialogContentText>
                  {t('Observation Sources')}
                </DialogContentText>
                <div className={classes.componentScroll}>
                  {
                    data?.origins && data.origins.map((value) => value.origin_actors.map((s, i) => (
                      <Link
                        key={i}
                        component="button"
                        variant="body2"
                        className={classes.link}
                        onClick={() => (history.push(`/data/entities/assessment_platform/${s.actor_ref.id}`))}
                      >
                        <LaunchIcon fontSize='small' /> {t(s.actor_ref.name)}
                      </Link>
                    )))
                  }
                </div>
                <Grid style={{ marginTop: '20px' }} spacing={3} container={true}>
                  <Grid item={true} xs={6}>
                    <DialogContentText>
                      {t('Methods')}
                    </DialogContentText>
                    {data?.methods && data.methods.map((value, i) => (
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
                    {data?.observation_types && data.observation_types.map((value, i) => (
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
                <div className={classes.componentScroll}>
                  {data.subjects && data.subjects.map((subject, i) => {
                    if (subject && subject.subject_context === 'target') {
                      return (
                        <div className={classes.observationContainer}>
                          <div style={{ height: '26px', padding: '0 10px 10px 0' }}>
                            <ItemIcon
                                key={i}
                                type={subject.subject_type}
                              />
                          </div>
                          <Link
                            component="button"
                            variant="body2"
                            className={classes.link}
                            onClick={() => (history.push(`/defender_hq/assets/devices/${subject.subject_ref.id}`))}
                          >
                            {t(subject.subject_ref.name)}
                            </Link>
                        </div>
                      );
                    }
                    return <></>;
                  })}
                </div>
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
                <div className={classes.componentScroll}>
                  {data.subjects && data.subjects.map((subject, i) => {
                    if (subject && subject.subject_context === 'secondary_target') {
                      return (
                        <div className={classes.observationContainer}>
                          <div style={{
                            height: '26px', padding: '0 10px 0 0', display: 'grid', placeItems: 'center',
                          }}>
                            <ItemIcon
                              key={i}
                              type={subject.subject_type}
                            />
                          </div>
                          <Link
                            component="button"
                            variant="body2"
                            className={classes.link}
                            onClick={() => (history.push(`/defender_hq/assets/software/${subject.subject_ref.id}`))}
                          >
                            {t(subject.subject_ref.name)}
                            </Link>
                        </div>
                      );
                    }
                    return <></>;
                  })}
                </div>
              </Grid>
            </Grid>
            <Divider />
          </DialogContentText>
        </DialogContent>
        <DialogActions style={{ marginLeft: '15px', display: 'flex', justifyContent: 'flex-start' }}>
          <Button
            onClick={() => handleCloseUpdate()}
            variant="outlined"
          >
            {t('Close')}
          </Button>
        </DialogActions>
      </>
    );
  }
}

RiskObservationPopover.propTypes = {
  displayUpdate: PropTypes.bool,
  handleCloseUpdate: PropTypes.func,
  data: PropTypes.object,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
  handleRemove: PropTypes.func,
  history: PropTypes.object,
};

export const riskObservationPopoverQuery = graphql`
  query RiskObservationPopoverQuery($id: ID!) {
    observation(id: $id){
      ...RiskObservationPopover_risk
    }
  }
`;

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
