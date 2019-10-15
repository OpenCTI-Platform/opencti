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
import EntityStixObservables from '../../stix_observables/EntityStixObservables';
import StixDomainEntityHeader from '../../common/stix_domain_entities/StixDomainEntityHeader';

const styles = () => ({
  container: {
    margin: 0,
    padding: '0 260px 0 0',
  },
  containerWithoutPadding: {
    margin: 0,
    padding: 0,
  },
  paper: {
    minHeight: '100%',
    margin: '5px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class IntrusionSetObservablesComponent extends Component {
  render() {
    const { classes, intrusionSet, location } = this.props;
    const link = `/dashboard/threats/intrusion_sets/${intrusionSet.id}/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/threats/intrusion_sets/${intrusionSet.id}/observables/relations/`,
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
          path="/dashboard/threats/intrusion_sets/:intrusionSetId/observables/relations/:relationId"
          render={routeProps => (
            <StixRelation
              entityId={intrusionSet.id}
              inversedRoles={[]}
              observable={true}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/threats/intrusion_sets/:intrusionSetId/observables"
          render={routeProps => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixObservables
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

IntrusionSetObservablesComponent.propTypes = {
  intrusionSet: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
};

const IntrusionSetObservables = createFragmentContainer(
  IntrusionSetObservablesComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetObservables_intrusionSet on IntrusionSet {
        id
        name
        alias
      }
    `,
  },
);

export default compose(
  withRouter,
  withStyles(styles),
)(IntrusionSetObservables);
