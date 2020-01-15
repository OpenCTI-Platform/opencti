import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Route, withRouter } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import CityPopover from './CityPopover';
import StixRelation from '../../common/stix_relations/StixRelation';
import EntityStixObservables from '../../signatures/stix_observables/EntityStixObservables';
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
    height: '100%',
    minHeight: '100%',
    margin: '5px 0 40px 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class CityObservablesComponent extends Component {
  render() {
    const { classes, city, location } = this.props;
    const link = `/dashboard/entities/cities/${city.id}/observables`;
    return (
      <div
        className={
          location.pathname.includes(
            `/dashboard/entities/cities/${city.id}/observables/relations/`,
          )
            ? classes.containerWithoutPadding
            : classes.container
        }
      >
        <StixDomainEntityHeader
          stixDomainEntity={city}
          PopoverComponent={<CityPopover />}
        />
        <Route
          exact
          path="/dashboard/entities/cities/:cityId/observables/relations/:relationId"
          render={(routeProps) => (
            <StixRelation
              entityId={city.id}
              {...routeProps}
            />
          )}
        />
        <Route
          exact
          path="/dashboard/entities/cities/:cityId/observables"
          render={(routeProps) => (
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityStixObservables
                entityId={city.id}
                relationType="localization"
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

CityObservablesComponent.propTypes = {
  city: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const CityObservables = createFragmentContainer(
  CityObservablesComponent,
  {
    city: graphql`
      fragment CityObservables_city on City {
        id
        name
        alias
      }
    `,
  },
);

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CityObservables);
