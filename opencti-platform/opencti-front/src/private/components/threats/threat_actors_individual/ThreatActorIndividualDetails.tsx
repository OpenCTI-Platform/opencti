import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, DramaMasks } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { Theme } from '../../../../components/Theme';
import {
  ThreatActorIndividualDetails_ThreatActorIndividual$data,
  ThreatActorIndividualDetails_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
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
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    margin: '0 5px 5px 0',
  },
}));

const ThreatActorIndividualDetailsFragment = graphql`
  fragment ThreatActorIndividualDetails_ThreatActorIndividual on ThreatActorIndividual {
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
`;

interface ThreatActorIndividualDetailsProps {
  threatActorIndividualData: ThreatActorIndividualDetails_ThreatActorIndividual$key;
}

const ThreatActorIndividualDetails: FunctionComponent<ThreatActorIndividualDetailsProps> = ({ threatActorIndividualData }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();
  const data: ThreatActorIndividualDetails_ThreatActorIndividual$data = useFragment(
    ThreatActorIndividualDetailsFragment,
    threatActorIndividualData,
  );
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
                source={data.description}
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
                type="threat-actor-sophistication-ov"
                value={data.sophistication}
                small
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
                value={data.resource_level}
                small
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Roles')}
              </Typography>
              {data.roles && (
                <List>
                  {data.roles.map((role) => (
                    <ListItem key={role} dense={true} divider={true}>
                      <ListItemIcon>
                        <DramaMasks />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <ItemOpenVocab
                            type="threat-actor-role-ov"
                            value={role}
                            small
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
              {data.goals && (
                <List>
                  {data.goals.map((goal) => (
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
              {data.threat_actor_types
                && data.threat_actor_types.map((threatActorIndividualType) => (
                  <Chip
                    key={threatActorIndividualType}
                    classes={{ root: classes.chip }}
                    label={threatActorIndividualType}
                  />
                ))}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {fldt(data.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fldt(data.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Primary motivation')}
              </Typography>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={data.primary_motivation}
                small
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              {data.secondary_motivations && (
                <List>
                  {data.secondary_motivations.map(
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
                              small
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
};

export default ThreatActorIndividualDetails;
