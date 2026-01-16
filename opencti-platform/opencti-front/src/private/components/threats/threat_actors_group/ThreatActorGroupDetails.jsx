import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, DramaMasks } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import Tooltip from '@mui/material/Tooltip';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel from '../../../../components/ImageCarousel';
import ThreatActorGroupLocation from './ThreatActorGroupLocation';
import { truncate } from '../../../../utils/String';
import Card from '@common/card/Card';
import Label from '../../../../components/common/label/Label';
import Tag from '../../../../components/common/tag/Tag';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 4,
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
      <Card title={t('Details')}>
        <Grid container={true} spacing={2}>
          <Grid item xs={hasImages ? 7 : 6}>
            <Grid container={true} spacing={2}>
              {hasImages && (
                <Grid item xs={4}>
                  <ImageCarousel data={threatActorGroup} />
                </Grid>
              )}
              <Grid item xs={hasImages ? 8 : 12}>
                <Label>
                  {t('Threat actor types')}
                </Label>
                <FieldOrEmpty source={threatActorGroup.threat_actor_types}>
                  {threatActorGroup.threat_actor_types
                    && threatActorGroup.threat_actor_types.map(
                      (threatActorGroupType) => (
                        <Tag
                          key={threatActorGroupType}
                          label={threatActorGroupType}
                        />
                      ),
                    )}
                </FieldOrEmpty>
                <Label
                  sx={{ marginTop: 2 }}
                >
                  {t('Description')}
                </Label>
                <ExpandableMarkdown
                  source={threatActorGroup.description}
                  limit={hasImages ? 400 : 600}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item xs={hasImages ? 5 : 6}>
            <ThreatActorGroupLocation threatActorGroup={threatActorGroup} />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('First seen')}
            </Label>
            {fldt(threatActorGroup.first_seen)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Last seen')}
            </Label>
            {fldt(threatActorGroup.last_seen)}
          </Grid>
        </Grid>
        <Grid container={true} spacing={2}>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Sophistication')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.sophistication}>
              <ItemOpenVocab
                type="threat-actor-group-sophistication-ov"
                value={threatActorGroup.sophistication}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Resource level')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.resource_level}>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={threatActorGroup.resource_level}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label
              sx={{ marginTop: 2 }}
            >
              {t('Primary motivation')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.primary_motivation}>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={threatActorGroup.primary_motivation}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label>
              {t('Roles')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.roles}>
              {threatActorGroup.roles && (
                <List>
                  {threatActorGroup.roles.map((role) => (
                    <ListItem key={role} dense={true} divider={true}>
                      <ListItemIcon>
                        <DramaMasks />
                      </ListItemIcon>
                      <ListItemText
                        primary={(
                          <ItemOpenVocab
                            type="threat-actor-group-role-ov"
                            value={role}
                          />
                        )}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label>
              {t('Goals')}
            </Label>
            <FieldOrEmpty source={threatActorGroup.goals}>
              {threatActorGroup.goals && (
                <List>
                  {threatActorGroup.goals.map((goal, index) => (
                    <ListItem key={`${index}:${goal}`} dense={true} divider={true}>
                      <ListItemIcon>
                        <BullseyeArrow />
                      </ListItemIcon>
                      <ListItemText
                        primary={(
                          <pre className={classes.smallPre}>
                            <Tooltip title={goal}>
                              {truncate(goal, 12)}
                            </Tooltip>
                          </pre>
                        )}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={4}>
            <Label>
              {t('Secondary motivations')}
            </Label>
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
                          primary={(
                            <ItemOpenVocab
                              type="attack-motivation-ov"
                              value={secondaryMotivation}
                            />
                          )}
                        />
                      </ListItem>
                    ),
                  )}
                </List>
              )}
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Card>
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
