import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import { IntrusionSetDetails_intrusionSet$data } from '@components/threats/intrusion_sets/__generated__/IntrusionSetDetails_intrusionSet.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import { useFormatter } from '../../../../components/i18n';
import IntrusionSetLocations from './IntrusionSetLocations';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ImageCarousel, { ImagesData } from '../../../../components/ImageCarousel';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import Card from '../../../../components/common/card/Card';
import Label from '../../../../components/common/label/Label';

type IntrusionSetDetailsProps = {
  intrusionSet: IntrusionSetDetails_intrusionSet$data;
};

const IntrusionSetDetailsComponent = ({ intrusionSet }: IntrusionSetDetailsProps) => {
  const { t_i18n, fldt } = useFormatter();

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
      <Card title={t_i18n('Details')}>
        <Grid container spacing={2}>
          <Grid item xs={hasImages ? 7 : 6}>
            <Grid container spacing={2}>
              {hasImages && (
                <Grid item xs={4}>
                  <ImageCarousel data={imagesCarousel} />
                </Grid>
              )}
              <Grid item xs={hasImages ? 8 : 12}>
                <Label>
                  {t_i18n('Description')}
                </Label>
                <ExpandableMarkdown
                  source={intrusionSet.description}
                  limit={hasImages ? 400 : 600}
                />
              </Grid>
            </Grid>
          </Grid>
          <Grid item xs={hasImages ? 5 : 6}>
            <IntrusionSetLocations intrusionSet={intrusionSet} />
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('First seen')}
            </Label>
            {fldt(intrusionSet.first_seen)}
            <Label
              sx={{ marginTop: 2 }}
            >
              {t_i18n('Last seen')}
            </Label>
            {fldt(intrusionSet.last_seen)}
          </Grid>
        </Grid>
        <Grid container spacing={2} mt={0}>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Resource level')}
            </Label>
            <FieldOrEmpty source={intrusionSet.resource_level}>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={intrusionSet.resource_level}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Primary motivation')}
            </Label>
            <FieldOrEmpty source={intrusionSet.primary_motivation}>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={intrusionSet.primary_motivation}
              />
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Goals')}
            </Label>
            <FieldOrEmpty source={intrusionSet.goals}>
              {intrusionSet.goals && (
                <List>
                  {intrusionSet.goals.map((goal) => (
                    <ListItem key={goal} dense divider>
                      <ListItemIcon>
                        <BullseyeArrow />
                      </ListItemIcon>
                      <ListItemText
                        primary={(
                          <pre style={{
                            display: 'inline-block',
                            margin: 0,
                            paddingTop: '7px',
                            paddingBottom: '4px',
                          }}
                          >
                            {goal}
                          </pre>
                        )}
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </FieldOrEmpty>
          </Grid>
          <Grid item xs={6}>
            <Label>
              {t_i18n('Secondary motivations')}
            </Label>
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
