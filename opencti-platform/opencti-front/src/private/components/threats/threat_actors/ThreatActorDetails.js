import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Chip from '@material-ui/core/Chip';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: 'rgba(0, 150, 136, 0.3)',
    color: '#ffffff',
    textTransform: 'uppercase',
    borderRadius: '0',
    margin: '0 5px 5px 0',
  },
});

class ThreatActorDetailsComponent extends Component {
  render() {
    const {
      t, classes, threatActor, fd,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={threatActor.description}
                limit={400}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Sophistication')}
              </Typography>
              {threatActor.sophistication && t(threatActor.sophistication)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Resource level')}
              </Typography>
              {threatActor.resource_level && t(threatActor.resource_level)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Goals')}
              </Typography>
              {threatActor.goals && (
                <List>
                  {threatActor.goals.map((goal) => (
                    <ListItem key={goal} dense={true} divider={true}>
                      <ListItemIcon>
                        <BullseyeArrow />
                      </ListItemIcon>
                      <ListItemText primary={goal} />
                    </ListItem>
                  ))}
                </List>
              )}
            </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Threat actor types')}
              </Typography>
              {threatActor.threat_actor_types
                && threatActor.threat_actor_types.map((threatActorType) => (
                  <Chip
                    key={threatActorType}
                    classes={{ root: classes.chip }}
                    label={threatActorType}
                  />
                ))}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {fd(threatActor.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fd(threatActor.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Primary motivation')}
              </Typography>
              {threatActor.primary_motivation
                && t(threatActor.primary_motivation)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              {threatActor.secondary_motivations && (
                <List>
                  {threatActor.secondary_motivations.map(
                    (secondaryMotivation) => (
                      <ListItem
                        key={secondaryMotivation}
                        dense={true}
                        divider={true}
                      >
                        <ListItemIcon>
                          <ArmFlexOutline />
                        </ListItemIcon>
                        <ListItemText primary={secondaryMotivation} />
                      </ListItem>
                    ),
                  )}
                </List>
              )}
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

ThreatActorDetailsComponent.propTypes = {
  threatActor: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const ThreatActorDetails = createFragmentContainer(
  ThreatActorDetailsComponent,
  {
    threatActor: graphql`
      fragment ThreatActorDetails_threatActor on ThreatActor {
        id
        first_seen
        last_seen
        description
        threat_actor_types
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        goals
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ThreatActorDetails);
