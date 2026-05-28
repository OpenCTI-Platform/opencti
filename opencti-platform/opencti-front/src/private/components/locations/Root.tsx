// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
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
        <Route path="/regions">
          <Route index element={boundaryWrapper(Regions)} />
          <Route path=":regionId">
            <Route path="*" index element={boundaryWrapper(RootRegion)} />
          </Route>
        </Route>
        <Route path="/countries">
          <Route index element={boundaryWrapper(Countries)} />
          <Route path=":countryId">
            <Route path="*" index element={boundaryWrapper(RootCountry)} />
          </Route>
        </Route>
        <Route path="/administrative_areas">
          <Route index element={boundaryWrapper(AdministrativeAreas)} />
          <Route path=":administrativeAreaId">
            <Route path="*" index element={boundaryWrapper(RootAdministrativeArea)} />
          </Route>
        </Route>
        <Route path="/cities">
          <Route index element={boundaryWrapper(Cities)} />
          <Route path=":cityId">
            <Route path="*" index element={boundaryWrapper(RootCity)} />
          </Route>
        </Route>
        <Route path="/positions">
          <Route index element={boundaryWrapper(Positions)} />
          <Route path=":positionId">
            <Route path="*" index element={boundaryWrapper(RootPosition)} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
};

export default Root;
