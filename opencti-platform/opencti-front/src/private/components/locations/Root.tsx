/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';
import { boundaryWrapper } from '../Error';

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
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/locations/${redirect}`} />}
        />
        <Route
          path="/regions"
          Component={boundaryWrapper(Regions)}
        />
        <Route
          path="/regions/:regionId/*"
          Component={boundaryWrapper(RootRegion)}
        />
        <Route
          path="/countries"
          Component={boundaryWrapper(Countries)}
        />
        <Route
          path="/countries/:countryId/*"
          Component={boundaryWrapper(RootCountry)}
        />
        <Route
          path="/administrative_areas"
          Component={boundaryWrapper(AdministrativeAreas)}
        />
        <Route
          path="/administrative_areas/:administrativeAreaId/*"
          Component={boundaryWrapper(RootAdministrativeArea)}
        />
        <Route
          path="/cities"
          Component={boundaryWrapper(Cities)}
        />
        <Route
          path="/cities/:cityId/*"
          Component={boundaryWrapper(RootCity)}
        />
        <Route
          path="/positions"
          Component={boundaryWrapper(Positions)}
        />
        <Route
          path="/positions/:positionId/*"
          Component={boundaryWrapper(RootPosition)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
