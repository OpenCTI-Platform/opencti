import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Sectors from './Sectors';
import RootSector from './sectors/Root';
import Regions from './Regions';
import RootRegion from './regions/Root';
import Countries from './Countries';
import RootCountry from './countries/Root';
import Cities from './Cities';
import Organizations from './Organizations';
import RootOrganization from './organizations/Root';
import Persons from './Persons';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/entities"
          render={() => (
            <Redirect to="/dashboard/entities/sectors" />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/sectors"
          component={Sectors}
        />
        <BoundaryRoute
          path="/dashboard/entities/sectors/:sectorId"
          render={routeProps => (
            <RootSector {...routeProps} me={me} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/regions"
          component={Regions}
        />
        <BoundaryRoute
          path="/dashboard/entities/regions/:regionId"
          render={routeProps => (
            <RootRegion {...routeProps} me={me} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/countries"
          component={Countries}
        />
        <BoundaryRoute
          path="/dashboard/entities/countries/:countryId"
          render={routeProps => (
            <RootCountry {...routeProps} me={me} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/cities"
          component={Cities}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/organizations"
          component={Organizations}
        />
        <BoundaryRoute
          path="/dashboard/entities/organizations/:organizationId"
          render={routeProps => (
            <RootOrganization {...routeProps} me={me} />
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/persons"
          component={Persons}
        />
      </Switch>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
