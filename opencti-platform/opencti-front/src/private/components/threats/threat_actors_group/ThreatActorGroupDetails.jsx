import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, DramaMasks } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';

const styles = (theme) => ({
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
    backgroundColor: theme.palette.background.accent,
    borderRadius: 5,
    color: theme.palette.text.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
});

class ThreatActorGroupDetailsComponent extends Component {
  render() {
    const { t, classes, threatActorGroup, fldt } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Description')}
              </Typography>
              <ExpandableMarkdown
                source={threatActorGroup.description}
                limit={400}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Sophistication')}
              </Typography>
              <ItemOpenVocab
                type="threat-actor-group-sophistication-ov"
                value={threatActorGroup.sophistication}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Resource level')}
              </Typography>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={threatActorGroup.resource_level}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Roles')}
              </Typography>
              {threatActorGroup.roles && (
                <List>
                  {threatActorGroup.roles.map((role) => (
                    <ListItem key={role} dense={true} divider={true}>
                      <ListItemIcon>
                        <DramaMasks />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <ItemOpenVocab
                            type="threat-actor-group-role-ov"
                            value={role}
                          />
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Goals')}
              </Typography>
              {threatActorGroup.goals && (
                <List>
                  {threatActorGroup.goals.map((goal) => (
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
                {t('Threat actor group types')}
              </Typography>
              {threatActorGroup.threat_actor_types
                && threatActorGroup.threat_actor_types.map((threatActorGroupType) => (
                  <Chip
                    key={threatActorGroupType}
                    classes={{ root: classes.chip }}
                    label={threatActorGroupType}
                  />
                ))}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {fldt(threatActorGroup.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fldt(threatActorGroup.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Primary motivation')}
              </Typography>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={threatActorGroup.primary_motivation}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              {threatActorGroup.secondary_motivations && (
                <List>
                  {threatActorGroup.secondary_motivations.map(
                    (secondaryMotivation) => (
                      <ListItem
                        key={secondaryMotivation}
                        dense={true}
                        divider={true}
                      >
                        <ListItemIcon>
                          <ArmFlexOutline />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <ItemOpenVocab
                              type="attack-motivation-ov"
                              value={secondaryMotivation}
                            />
                          }
                        />
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

ThreatActorGroupDetailsComponent.propTypes = {
  threatActorGroup: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
};

const ThreatActorGroupDetails = createFragmentContainer(
  ThreatActorGroupDetailsComponent,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupDetails_ThreatActorGroup on ThreatActorGroup {
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
        roles
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ThreatActorGroupDetails);
