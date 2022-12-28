/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
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
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import AdministrativeAreas from './AdministrativeAreas';
import RootAdministrativeArea from './administrative_areas/Root';

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Region')) {
    redirect = 'regions';
  } else if (!useIsHiddenEntity('Country')) {
    redirect = 'countries';
  } else if (!helper.isEntityTypeHidden('AdministrativeArea')) {
    redirect = 'areas';
  } else if (!useIsHiddenEntity('City')) {
    redirect = 'cities';
  } else if (!useIsHiddenEntity('Position')) {
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
            path="/dashboard/locations/areas"
            component={AdministrativeAreas}
        />
        <BoundaryRoute
            path="/dashboard/locations/areas/:areaId"
            component={RootAdministrativeArea}
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
