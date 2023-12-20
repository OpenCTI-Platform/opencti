/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Countries = lazy(() => import('./Countries'));
const RootCountry = lazy(() => import('./countries/Root'));
const Regions = lazy(() => import('./Regions'));
const RootRegion = lazy(() => import('./regions/Root'));
const Cities = lazy(() => import('./Cities'));
const RootCity = lazy(() => import('./cities/Root'));
const Positions = lazy(() => import('./Positions'));
const RootPosition = lazy(() => import('./positions/Root'));
const AdministrativeAreas = lazy(() => import('./AdministrativeAreas'));
const RootAdministrativeArea = lazy(() => import('./administrative_areas/Root'));

const Root = () => {
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Region')) {
    redirect = 'regions';
  } else if (!useIsHiddenEntity('Country')) {
    redirect = 'countries';
  } else if (!useIsHiddenEntity('Administrative-Area')) {
    redirect = 'administrative_areas';
  } else if (!useIsHiddenEntity('City')) {
    redirect = 'cities';
  } else if (!useIsHiddenEntity('Position')) {
    redirect = 'positions';
  }
  return (
    <Suspense fallback={<Loader />}>
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
          path="/dashboard/locations/administrative_areas"
          component={AdministrativeAreas}
        />
        <BoundaryRoute
          path="/dashboard/locations/administrative_areas/:administrativeAreaId"
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
    </Suspense>
  );
};

export default Root;
