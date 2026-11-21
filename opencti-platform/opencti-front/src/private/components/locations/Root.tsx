import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
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
  const redirect = useFirstVisiblePath(sectionEntries('locations'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/regions"
          element={(
            <EntryGuard path="/dashboard/locations/regions">
              {boundaryWrapper(Regions)}
            </EntryGuard>
          )}
        />
        <Route
          path="/regions/:regionId/*"
          element={(
            <EntryGuard path="/dashboard/locations/regions">
              {boundaryWrapper(RootRegion)}
            </EntryGuard>
          )}
        />
        <Route
          path="/countries"
          element={(
            <EntryGuard path="/dashboard/locations/countries">
              {boundaryWrapper(Countries)}
            </EntryGuard>
          )}
        />
        <Route
          path="/countries/:countryId/*"
          element={(
            <EntryGuard path="/dashboard/locations/countries">
              {boundaryWrapper(RootCountry)}
            </EntryGuard>
          )}
        />
        <Route
          path="/administrative_areas"
          element={(
            <EntryGuard path="/dashboard/locations/administrative_areas">
              {boundaryWrapper(AdministrativeAreas)}
            </EntryGuard>
          )}
        />
        <Route
          path="/administrative_areas/:administrativeAreaId/*"
          element={(
            <EntryGuard path="/dashboard/locations/administrative_areas">
              {boundaryWrapper(RootAdministrativeArea)}
            </EntryGuard>
          )}
        />
        <Route
          path="/cities"
          element={(
            <EntryGuard path="/dashboard/locations/cities">
              {boundaryWrapper(Cities)}
            </EntryGuard>
          )}
        />
        <Route
          path="/cities/:cityId/*"
          element={(
            <EntryGuard path="/dashboard/locations/cities">
              {boundaryWrapper(RootCity)}
            </EntryGuard>
          )}
        />
        <Route
          path="/positions"
          element={(
            <EntryGuard path="/dashboard/locations/positions">
              {boundaryWrapper(Positions)}
            </EntryGuard>
          )}
        />
        <Route
          path="/positions/:positionId/*"
          element={(
            <EntryGuard path="/dashboard/locations/positions">
              {boundaryWrapper(RootPosition)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
