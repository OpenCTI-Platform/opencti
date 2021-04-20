import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import { BullseyeArrow, ArmFlexOutline } from 'mdi-material-ui';
import ListItemText from '@material-ui/core/ListItemText';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import inject18n from '../../../../components/i18n';
import IntrusionSetLocations from './IntrusionSetLocations';

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

class IntrusionSetDetailsComponent extends Component {
  render() {
    const {
      t, classes, intrusionSet, fd,
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
                source={intrusionSet.description}
                limit={400}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Resource level')}
              </Typography>
              {intrusionSet.resource_level && t(intrusionSet.resource_level)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Goals')}
              </Typography>
              {intrusionSet.goals && (
                <List>
                  {intrusionSet.goals.map((goal) => (
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
              <IntrusionSetLocations intrusionSet={intrusionSet} />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {fd(intrusionSet.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {fd(intrusionSet.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Primary motivation')}
              </Typography>
              {intrusionSet.primary_motivation && (
                <List>
                  <ListItem dense={true} divider={true}>
                    <ListItemIcon>
                      <ArmFlexOutline />
                    </ListItemIcon>
                    <ListItemText
                      primary={t(intrusionSet.primary_motivation)}
                    />
                  </ListItem>
                </List>
              )}
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
                        <ListItemText primary={t(secondaryMotivation)} />
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
        ...IntrusionSetLocations_intrusionSet
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(IntrusionSetDetails);
