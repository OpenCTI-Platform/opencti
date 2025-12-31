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
          element={<Navigate to={`/dashboard/locations/${redirect}`} replace={true} />}
        />
        <Route
          path="/regions"
          element={boundaryWrapper(Regions)}
        />
        <Route
          path="/regions/:regionId/*"
          element={boundaryWrapper(RootRegion)}
        />
        <Route
          path="/countries"
          element={boundaryWrapper(Countries)}
        />
        <Route
          path="/countries/:countryId/*"
          element={boundaryWrapper(RootCountry)}
        />
        <Route
          path="/administrative_areas"
          element={boundaryWrapper(AdministrativeAreas)}
        />
        <Route
          path="/administrative_areas/:administrativeAreaId/*"
          element={boundaryWrapper(RootAdministrativeArea)}
        />
        <Route
          path="/cities"
          element={boundaryWrapper(Cities)}
        />
        <Route
          path="/cities/:cityId/*"
          element={boundaryWrapper(RootCity)}
        />
        <Route
          path="/positions"
          element={boundaryWrapper(Positions)}
        />
        <Route
          path="/positions/:positionId/*"
          element={boundaryWrapper(RootPosition)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
