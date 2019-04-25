import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../components/i18n';
import IntrusionSetHeader from './IntrusionSetHeader';
import StixRelation from '../stix_relation/StixRelation';
import EntityStixObservables from '../stix_observable/EntityStixObservables';

const styles = theme => ({
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
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class IntrusionSetObservablesComponent extends Component {
  render() {
    const { classes, intrusionSet, location } = this.props;
    const link = `/dashboard/knowledge/intrusion_sets/${
      intrusionSet.id
    }/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/knowledge/intrusion_sets/${
              intrusionSet.id
            }/observables/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <IntrusionSetHeader intrusionSet={intrusionSet} variant="noalias" />
        <Route
          exact
          path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/observables/relations/:relationId"
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
          path="/dashboard/knowledge/intrusion_sets/:intrusionSetId/observables"
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
  t: PropTypes.func,
};

const IntrusionSetObservables = createFragmentContainer(
  IntrusionSetObservablesComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetObservables_intrusionSet on IntrusionSet {
        id
        ...IntrusionSetHeader_intrusionSet
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IntrusionSetObservables);
