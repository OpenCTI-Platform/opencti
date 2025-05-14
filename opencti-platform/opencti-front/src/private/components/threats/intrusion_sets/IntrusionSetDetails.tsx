import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import { useTheme } from '@mui/material/styles';
import { IntrusionSetDetails_intrusionSet$data } from '@components/threats/intrusion_sets/__generated__/IntrusionSetDetails_intrusionSet.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import IntrusionSetLocations from './IntrusionSetLocations';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ImageCarousel, { ImagesData } from '../../../../components/ImageCarousel';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

type IntrusionSetDetailsProps = {
  intrusionSet: IntrusionSetDetails_intrusionSet$data
};

const IntrusionSetDetailsComponent = ({ intrusionSet }: IntrusionSetDetailsProps) => {
  const { t_i18n, fldt } = useFormatter();
  const theme = useTheme();

  const imagesCarousel: { images: ImagesData } = {
    images: {
      edges: (intrusionSet.images?.edges ?? []).filter((n) => n?.node?.metaData?.inCarousel),
    } as ImagesData,
  };

  const hasImages = intrusionSet.images?.edges && intrusionSet.images.edges.filter((n) => (
    n?.node?.metaData?.inCarousel
  )).length > 0;

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4">
        {t_i18n('Details')}
      </Typography>
      <Paper
        sx={{
          marginTop: theme.spacing(1),
          padding: '15px',
          borderRadius: '4px',
        }}
        className={'paper-for-grid'}
        variant="outlined"
      >
        <Grid container spacing={3}>
          <Grid item xs={hasImages ? 7 : 6}>
            <Grid container spacing={3}>
              {hasImages && (
                <Grid item xs={4}>
                  <ImageCarousel data={imagesCarousel} />
                </Grid>
              )}
              <Grid item xs={hasImages ? 8 : 12}>
                <Typography variant="h3" gutterBottom>
                  {t_i18n('Description')}
                </Typography>
                <ExpandableMarkdown
                  source={intrusionSet.description}
                  limit={hasImages ? 400 : 600}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item xs={hasImages ? 5 : 6}>
            <IntrusionSetLocations intrusionSet={intrusionSet} />
            <Typography
              variant="h3"
              gutterBottom
              style={{ marginTop: 20 }}
            >
              {t_i18n('First seen')}
            </Typography>
            {fldt(intrusionSet.first_seen)}
            <Typography
              variant="h3"
              gutterBottom
              style={{ marginTop: 20 }}
            >
              {t_i18n('Last seen')}
            </Typography>
            {fldt(intrusionSet.last_seen)}
          </Grid>
        </Grid>
        <Grid container spacing={3}>
          <Grid item xs={6}>
            <Typography
              variant="h3"
              gutterBottom
              style={{ marginTop: 20 }}
            >
              {t_i18n('Resource level')}
            </Typography>
            <FieldOrEmpty source={intrusionSet.resource_level}>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={intrusionSet.resource_level}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Typography
              variant="h3"
              gutterBottom
              style={{ marginTop: 20 }}
            >
              {t_i18n('Primary motivation')}
            </Typography>
            <FieldOrEmpty source={intrusionSet.primary_motivation}>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={intrusionSet.primary_motivation}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Typography
              variant="h3"
              gutterBottom
              style={{ marginTop: 20 }}
            >
              {t_i18n('Goals')}
            </Typography>
            <FieldOrEmpty source={intrusionSet.goals}>
              {intrusionSet.goals && (
                <List>
                  {intrusionSet.goals.map((goal) => (
                    <ListItem key={goal} dense divider>
                      <ListItemIcon>
                        <BullseyeArrow />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <pre style={{
                            display: 'inline-block',
                            margin: 0,
                            paddingTop: '7px',
                            paddingBottom: '4px',
                          }}
                          >
                            {goal}
                          </pre>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Typography
              variant="h3"
              gutterBottom
              style={{ marginTop: 20 }}
            >
              {t_i18n('Secondary motivations')}
            </Typography>
            <FieldOrEmpty source={intrusionSet.secondary_motivations}>
              {intrusionSet.secondary_motivations && (
              <List>
                {intrusionSet.secondary_motivations.map(
                  (secondaryMotivation) => (
                    <ListItem
                      key={secondaryMotivation}
                      dense
                      divider
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
};

const IntrusionSetDetails = createFragmentContainer(
  IntrusionSetDetailsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetDetails_intrusionSet on IntrusionSet {
        id
        first_seen
        last_seen
        description
        resource_level
        primary_motivation
        secondary_motivations
        goals
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
        ...IntrusionSetLocations_intrusionSet
      }
    `,
  },
);

export default IntrusionSetDetails;
