import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, DramaMasks } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import { Theme } from '../../../../components/Theme';
import {
  ThreatActorIndividualDetails_ThreatActorIndividual$data,
  ThreatActorIndividualDetails_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel from '../../../../components/ImageCarousel';
import ThreatActorIndividualLocation from './ThreatActorIndividualLocation';

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
  smallPre: {
    display: 'inline-block',
    margin: 0,
    paddingTop: '7px',
    paddingBottom: '4px',
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
    ...ThreatActorIndividualLocations_locations
  }
`;

interface ThreatActorIndividualDetailsProps {
  threatActorIndividualData: ThreatActorIndividualDetails_ThreatActorIndividual$key;
}

const ThreatActorIndividualDetails: FunctionComponent<
ThreatActorIndividualDetailsProps
> = ({ threatActorIndividualData }) => {
  const classes = useStyles();
  const { t, fldt } = useFormatter();
  const data: ThreatActorIndividualDetails_ThreatActorIndividual$data = useFragment(
    ThreatActorIndividualDetailsFragment,
    threatActorIndividualData,
  );
  const hasImages = (data.images?.edges?.length ?? 0) > 0;
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
                  <ImageCarousel data={data} />
                </Grid>
              )}
              <Grid item={true} xs={hasImages ? 8 : 12}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Threat actor types')}
                </Typography>
                <FieldOrEmpty source={data.threat_actor_types}>
                  {data.threat_actor_types
                    && data.threat_actor_types.map((threatActorIndividualType) => (
                      <Chip
                        key={threatActorIndividualType}
                        classes={{ root: classes.chip }}
                        label={threatActorIndividualType}
                      />
                    ))}
                </FieldOrEmpty>
                <Typography
                  variant="h3"
                  gutterBottom={true}
                  style={{ marginTop: 20 }}
                >
                  {t('Description')}
                </Typography>
                <ExpandableMarkdown
                  source={data.description}
                  limit={hasImages ? 400 : 600}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item={true} xs={5}>
            <ThreatActorIndividualLocation threatActorIndividual={data} />
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
              type="threat-actor-individual-sophistication-ov"
              value={data.sophistication}
              small
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
              value={data.resource_level}
              small
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
              value={data.primary_motivation}
              small
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
            <FieldOrEmpty source={data.roles}>
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
                            type="threat-actor-individual-role-ov"
                            value={role}
                            small
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
            <FieldOrEmpty source={data.goals}>
              {data.goals && (
                <List>
                  {data.goals.map((goal) => (
                    <ListItem key={goal} dense={true} divider={true}>
                      <ListItemIcon>
                        <BullseyeArrow />
                      </ListItemIcon>
                      <ListItemText
                        primary={<pre className={classes.smallPre}>{goal}</pre>}
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
            <FieldOrEmpty source={data.secondary_motivations}>
              {data.secondary_motivations && (
                <List>
                  {data.secondary_motivations.map((secondaryMotivation) => (
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
                  ))}
                </List>
              )}
            </FieldOrEmpty>
          </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default ThreatActorIndividualDetails;
