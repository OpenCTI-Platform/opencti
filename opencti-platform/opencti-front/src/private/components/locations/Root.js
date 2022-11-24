import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Countries from './Countries';
import RootCountry from './countries/Root';
import Regions from './Regions';
import RootRegion from './regions/Root';
import Cities from './Cities';
import RootCity from './cities/Root';
import Positions from './Positions';
import RootPosition from './positions/Root';
import { UserContext } from '../../../utils/hooks/useAuth';

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => {
          let redirect = null;
          if (!helper.isEntityTypeHidden('Region')) {
            redirect = 'regions';
          } else if (!helper.isEntityTypeHidden('Country')) {
            redirect = 'countries';
          } else if (!helper.isEntityTypeHidden('City')) {
            redirect = 'cities';
          } else if (!helper.isEntityTypeHidden('Position')) {
            redirect = 'positions';
          }
          return (
            <Switch>
              <BoundaryRoute
                exact
                path="/dashboard/locations"
                render={() => (
                  <Redirect to={`/dashboard/locations/${redirect}`} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/locations/regions"
                component={Regions}
              />
              <BoundaryRoute
                path="/dashboard/locations/regions/:regionId"
                render={(routeProps) => <RootRegion {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/locations/countries"
                component={Countries}
              />
              <BoundaryRoute
                path="/dashboard/locations/countries/:countryId"
                render={(routeProps) => <RootCountry {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/locations/cities"
                component={Cities}
              />
              <BoundaryRoute
                path="/dashboard/locations/cities/:cityId"
                render={(routeProps) => <RootCity {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/locations/positions"
                component={Positions}
              />
              <BoundaryRoute
                path="/dashboard/locations/positions/:positionId"
                render={(routeProps) => (
                  <RootPosition {...routeProps} me={me} />
                )}
              />
            </Switch>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
