import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline, DramaMasks } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import CardTitle from '@common/card/CardTitle';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import type { Theme } from '../../../../components/Theme';
import {
  ThreatActorIndividualDetails_ThreatActorIndividual$data,
  ThreatActorIndividualDetails_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualDetails_ThreatActorIndividual.graphql';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import ImageCarousel, { ImagesData } from '../../../../components/ImageCarousel';
import ThreatActorIndividualLocation from './ThreatActorIndividualLocation';
import ThreatActorIndividualDetailsChips from './ThreatActorIndividualDetailsChips';
import Card from '../../../../components/common/card/Card';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    borderRadius: 4,
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
  fragment ThreatActorIndividualDetails_ThreatActorIndividual on ThreatActorIndividual
  {
    id
    first_seen
    last_seen
    description
    threat_actor_types
    sophistication
    resource_level
    personal_motivations
    primary_motivation
    secondary_motivations
    goals
    roles
    stixCoreRelationships {
      edges {
        node {
          id
          relationship_type
          to {
            ... on Individual {
              id
              name
            }
            ... on Persona {
              id
              observable_value
              persona_type
            }
          }
        }
      }
    }
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
  const { t_i18n, fldt } = useFormatter();
  const data: ThreatActorIndividualDetails_ThreatActorIndividual$data = useFragment(
    ThreatActorIndividualDetailsFragment,
    threatActorIndividualData,
  );

  const imagesCarousel: { images: ImagesData } = {
    images: {
      edges: (data.images?.edges ?? []).filter((n) => n?.node?.metaData?.inCarousel),
    } as ImagesData,
  };
  const hasImages = imagesCarousel.images?.edges ? imagesCarousel.images.edges.length > 0 : false;

  return (
    <Card title={t_i18n('Details')}>
      <Grid container={true} spacing={3}>
        <Grid item xs={hasImages ? 7 : 6}>
          <Grid container={true} spacing={3}>
            {hasImages && (
              <Grid item xs={4}>
                <ImageCarousel data={imagesCarousel} />
              </Grid>
            )}
            <Grid item xs={hasImages ? 8 : 12}>
              <Typography variant="h3" gutterBottom={true}>
                {t_i18n('Threat actor types')}
              </Typography>
              <FieldOrEmpty source={data.threat_actor_types}>
                {data.threat_actor_types?.map((threatActorIndividualType) => (
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
                {t_i18n('Description')}
              </Typography>
              <ExpandableMarkdown
                source={data.description}
                limit={hasImages ? 400 : 600}
              />
            </Grid>
          </Grid>
        </Grid>
        <Grid item xs={hasImages ? 5 : 6}>
          <ThreatActorIndividualDetailsChips
            data={data}
            relType="known-as"
          />
          <ThreatActorIndividualDetailsChips
            data={data}
            relType="impersonates"
          />
          <ThreatActorIndividualLocation threatActorIndividual={data} />
          <CardTitle sx={{ marginTop: '20px' }}>
            {t_i18n('First seen')}
          </CardTitle>
          {fldt(data.first_seen)}
          <CardTitle sx={{ marginTop: '20px' }}>
            {t_i18n('Last seen')}
          </CardTitle>
          {fldt(data.last_seen)}
        </Grid>
      </Grid>
      <Grid container={true} spacing={3}>
        <Grid item xs={4}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Sophistication')}
          </Typography>
          <FieldOrEmpty source={data.sophistication}>
            <ItemOpenVocab
              type="threat-actor-individual-sophistication-ov"
              value={data.sophistication}
              small
            />
          </FieldOrEmpty>
        </Grid>
        <Grid item xs={4}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Resource level')}
          </Typography>
          <FieldOrEmpty source={data.resource_level}>
            <ItemOpenVocab
              type="attack-resource-level-ov"
              value={data.resource_level}
              small
            />
          </FieldOrEmpty>
        </Grid>
        <Grid item xs={4}>
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t_i18n('Primary motivation')}
          </Typography>
          <FieldOrEmpty source={data.primary_motivation}>
            <ItemOpenVocab
              type="attack-motivation-ov"
              value={data.primary_motivation}
              small
            />
          </FieldOrEmpty>
        </Grid>
        <Grid item xs={4}>
          <CardTitle sx={{ marginTop: '20px' }}>
            {t_i18n('Roles')}
          </CardTitle>
          <FieldOrEmpty source={data.roles}>
            {data.roles && (
              <List>
                {data.roles.map((role) => (
                  <ListItem key={role} dense={true} divider={true}>
                    <ListItemIcon>
                      <DramaMasks />
                    </ListItemIcon>
                    <ListItemText
                      primary={(
                        <ItemOpenVocab
                          type="threat-actor-individual-role-ov"
                          value={role}
                          small
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
          <CardTitle sx={{ marginTop: '20px' }}>
            {t_i18n('Goals')}
          </CardTitle>
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
        <Grid item xs={4}>
          <CardTitle sx={{ marginTop: '20px' }}>
            {t_i18n('Secondary motivations')}
          </CardTitle>
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
                      primary={(
                        <ItemOpenVocab
                          type="attack-motivation-ov"
                          value={secondaryMotivation}
                          small
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
          <CardTitle sx={{ marginTop: '20px' }}>
            {t_i18n('Personal motivations')}
          </CardTitle>
          <FieldOrEmpty source={data.personal_motivations}>
            {data.personal_motivations && (
              <List>
                {data.personal_motivations.map((personalMotivation) => (
                  <ListItem
                    key={personalMotivation}
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
                          value={personalMotivation}
                          small
                        />
                      )}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </FieldOrEmpty>
        </Grid>
      </Grid>
    </Card>
  );
};

export default ThreatActorIndividualDetails;
