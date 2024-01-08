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
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel from '../../../../components/ImageCarousel';
import ThreatActorGroupLocation from './ThreatActorGroupLocation';

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
  smallPre: {
    display: 'inline-block',
    margin: 0,
    paddingTop: '7px',
    paddingBottom: '4px',
  },
});

class ThreatActorGroupDetailsComponent extends Component {
  render() {
    const { t, classes, threatActorGroup, fldt } = this.props;
    const hasImages = (threatActorGroup.images?.edges ?? []).filter(
      (n) => n?.node?.metaData?.inCarousel,
    ).length > 0;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={hasImages ? 7 : 6}>
              <Grid container={true} spacing={3}>
                {hasImages && (
                  <Grid item={true} xs={4}>
                    <ImageCarousel data={threatActorGroup} />
                  </Grid>
                )}
                <Grid item={true} xs={hasImages ? 8 : 12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Threat actor types')}
                  </Typography>
                  <FieldOrEmpty source={threatActorGroup.threat_actor_types}>
                    {threatActorGroup.threat_actor_types
                      && threatActorGroup.threat_actor_types.map(
                        (threatActorGroupType) => (
                          <Chip
                            key={threatActorGroupType}
                            classes={{ root: classes.chip }}
                            label={threatActorGroupType}
                          />
                        ),
                      )}
                  </FieldOrEmpty>
                  <Typography
                    variant="h3"
                    gutterBottom={true}
                    style={{ marginTop: 20 }}
                  >
                    {t('Description')}
                  </Typography>
                  <ExpandableMarkdown
                    source={threatActorGroup.description}
                    limit={hasImages ? 400 : 600}
                  />
                </Grid>
              </Grid>
            </Grid>
            <Grid item={true} xs={hasImages ? 5 : 6}>
              <ThreatActorGroupLocation threatActorGroup={threatActorGroup} />
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
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={4}>
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
            </Grid>
            <Grid item={true} xs={4}>
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
            </Grid>
            <Grid item={true} xs={4}>
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
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Roles')}
              </Typography>
              <FieldOrEmpty source={threatActorGroup.roles}>
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
              </FieldOrEmpty>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Goals')}
              </Typography>
              <FieldOrEmpty source={threatActorGroup.goals}>
                {threatActorGroup.goals && (
                  <List>
                    {threatActorGroup.goals.map((goal, index) => (
                      <ListItem key={`${index}:${goal}`} dense={true} divider={true}>
                        <ListItemIcon>
                          <BullseyeArrow />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <pre className={classes.smallPre}>{goal}</pre>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </FieldOrEmpty>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              <FieldOrEmpty source={threatActorGroup.secondary_motivations}>
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
              </FieldOrEmpty>
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
        images: importFiles(prefixMimeType: "image/") {
          edges {
            node {
              id
              name
              metaData {
                mimetype
                order
                inCarousel
                description
              }
            }
          }
        }
        ...ThreatActorGroupLocations_locations
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(ThreatActorGroupDetails);
