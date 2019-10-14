import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class IntrusionSetDetailsComponent extends Component {
  render() {
    const {
      t, fld, classes, intrusionSet,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('First seen')}
          </Typography>
          {fld(intrusionSet.first_seen)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Last seen')}
          </Typography>
          {fld(intrusionSet.last_seen)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Sophistication')}
          </Typography>
          {t(
            `${
              intrusionSet.sophistication
                ? `sophistication_${intrusionSet.sophistication}`
                : 'sophistication_unkown'
            }`,
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Resource level')}
          </Typography>
          {t(
            `${
              intrusionSet.resource_level
                ? `resource_${intrusionSet.resource_level}`
                : 'resource_unkown'
            }`,
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Primary motivation')}
          </Typography>
          {t(
            `${
              intrusionSet.primary_motivation
                ? `motivation_${intrusionSet.primary_motivation}`
                : 'motivation_unpredictable'
            }`,
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Secondary motivation')}
          </Typography>
          {t(
            `${
              intrusionSet.secondary_motivation
                ? `motivation_${intrusionSet.secondary_motivation}`
                : 'motivation_unknown'
            }`,
          )}
        </Paper>
      </div>
    );
  }
}

IntrusionSetDetailsComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IntrusionSetDetails = createFragmentContainer(
  IntrusionSetDetailsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetDetails_intrusionSet on IntrusionSet {
        id
        first_seen
        last_seen
        sophistication
        resource_level
        primary_motivation
        secondary_motivation
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetDetails);
