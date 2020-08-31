import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, join, map } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Markdown from 'react-markdown';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabelsView from '../../common/stix_core_objects/StixCoreObjectLabelsView';
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
    const secondaryMotivations = intrusionSet.secondary_motivations
      ? map(
        (secondaryMotivation) => t(`motivation_${secondaryMotivation}`),
        intrusionSet.secondary_motivations,
      )
      : [];
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <StixCoreObjectLabelsView
            labels={intrusionSet.objectLabel}
            id={intrusionSet.id}
          />
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
            {t('Secondary motivations')}
          </Typography>
          <Markdown
            className="markdown"
            source={`+ ${join('\n\n+ ', secondaryMotivations)}`}
          />
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
        resource_level
        primary_motivation
        secondary_motivations
        creator {
          id
          name
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(IntrusionSetDetails);
