import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import StixDomainEntityTags from '../../common/stix_domain_entities/StixDomainEntityTags';
import ItemCreator from '../../../../components/ItemCreator';

const styles = () => ({
  paper: {
    height: '100%',
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
          <StixDomainEntityTags tags={intrusionSet.tags} id={intrusionSet.id} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creator')}
          </Typography>
          <ItemCreator creator={intrusionSet.creator} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
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
        creator {
          id
          name
        }
        tags {
          edges {
            node {
              id
              tag_type
              value
              color
            }
            relation {
              id
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(IntrusionSetDetails);
