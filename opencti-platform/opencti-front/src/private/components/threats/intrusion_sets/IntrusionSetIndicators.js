import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import IntrusionSetPopover from './IntrusionSetPopover';
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityIndicators from '../../signatures/indicators/EntityIndicators';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
  },
  containerWithoutPadding: {
    margin: 0,
    padding: 0,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class IntrusionSetIndicatorsComponent extends Component {
  render() {
    const { classes, intrusionSet, location } = this.props;
    const link = `/dashboard/threats/intrusion_sets/${intrusionSet.id}/indicators`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/intrusion_sets/${intrusionSet.id}/indicators/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <StixDomainEntityHeader
          stixDomainEntity={intrusionSet}
          PopoverComponent={<IntrusionSetPopover />}
        />
        <Route
          exact
          path="/dashboard/threats/intrusion_sets/:intrusionSetId/indicators/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={intrusionSet.id}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/intrusion_sets/:intrusionSetId/indicators"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityIndicators
                entityId={intrusionSet.id}
                relationType="indicates"
                entityLink={link}
                {...routeProps}
              />
            </Paper>
          )}
        />
      </div>
    );
  }
}

IntrusionSetIndicatorsComponent.propTypes = {
  intrusionSet: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
};

const IntrusionSetIndicators = createFragmentContainer(
  IntrusionSetIndicatorsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetIndicators_intrusionSet on IntrusionSet {
        id
        name
        alias
      }
    `,
  },
);

export default compose(withRouter, withStyles(styles))(IntrusionSetIndicators);
