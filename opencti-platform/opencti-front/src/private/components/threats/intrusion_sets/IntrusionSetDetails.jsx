import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline } from 'mdi-material-ui';
import ListItemText from '@mui/material/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import IntrusionSetLocations from './IntrusionSetLocations';
import ItemOpenVocab from '../../../../components/ItemOpenVocab';
import ImageCarousel from '../../../../components/ImageCarousel';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

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

class IntrusionSetDetailsComponent extends Component {
  render() {
    const { t, classes, intrusionSet, fldt } = this.props;
    const hasImages = (intrusionSet.images?.edges ?? []).filter(
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
                    <ImageCarousel data={intrusionSet} />
                  </Grid>
                )}
                <Grid item={true} xs={hasImages ? 8 : 12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Description')}
                  </Typography>
                  <ExpandableMarkdown
                    source={intrusionSet.description}
                    limit={hasImages ? 400 : 600}
                  />
                </Grid>
              </Grid>
            </Grid>
            <Grid item={true} xs={hasImages ? 5 : 6}>
              <IntrusionSetLocations intrusionSet={intrusionSet} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {fldt(intrusionSet.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fldt(intrusionSet.last_seen)}
            </Grid>
          </Grid>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Resource level')}
              </Typography>
              <ItemOpenVocab
                type="attack-resource-level-ov"
                value={intrusionSet.resource_level}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Primary motivation')}
              </Typography>
              <ItemOpenVocab
                type="attack-motivation-ov"
                value={intrusionSet.primary_motivation}
              />
            </Grid>
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Goals')}
              </Typography>
              <FieldOrEmpty source={intrusionSet.goals}>
                {intrusionSet.goals && (
                  <List>
                    {intrusionSet.goals.map((goal) => (
                      <ListItem key={goal} dense={true} divider={true}>
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
            <Grid item={true} xs={6}>
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Secondary motivations')}
              </Typography>
              {intrusionSet.secondary_motivations && (
                <List>
                  {intrusionSet.secondary_motivations.map(
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

IntrusionSetDetailsComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fd: PropTypes.func,
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

export default compose(inject18n, withStyles(styles))(IntrusionSetDetails);
