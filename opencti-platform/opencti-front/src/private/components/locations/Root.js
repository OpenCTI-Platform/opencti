import React, { useContext } from 'react';
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

const Root = () => {
  const { helper } = useContext(UserContext);
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
        render={() => <Redirect to={`/dashboard/locations/${redirect}`} />}
      />
      <BoundaryRoute
        exact
        path="/dashboard/locations/regions"
        component={Regions}
      />
      <BoundaryRoute
        path="/dashboard/locations/regions/:regionId"
        component={RootRegion}
      />
      <BoundaryRoute
        exact
        path="/dashboard/locations/countries"
        component={Countries}
      />
      <BoundaryRoute
        path="/dashboard/locations/countries/:countryId"
        component={RootCountry}
      />
      <BoundaryRoute
        exact
        path="/dashboard/locations/cities"
        component={Cities}
      />
      <BoundaryRoute
        path="/dashboard/locations/cities/:cityId"
        component={RootCity}
      />
      <BoundaryRoute
        exact
        path="/dashboard/locations/positions"
        component={Positions}
      />
      <BoundaryRoute
        path="/dashboard/locations/positions/:positionId"
        component={RootPosition}
      />
    </Switch>
  );
};

export default Root;
