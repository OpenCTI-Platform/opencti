import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import EntryGuard from '../nav/EntryGuard';
import { boundaryWrapper } from '../Error';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
import Loader from '../../../components/Loader';

const Sectors = lazy(() => import('./Sectors'));
const RootSector = lazy(() => import('./sectors/Root'));
const Events = lazy(() => import('./Events'));
const RootEvent = lazy(() => import('./events/Root'));
const Organizations = lazy(() => import('./Organizations'));
const RootOrganization = lazy(() => import('./organizations/Root'));
const Security = lazy(() => import('./SecurityPlatforms'));
const RootSecurity = lazy(() => import('./securityPlatforms/Root'));
const Systems = lazy(() => import('./Systems'));
const RootSystem = lazy(() => import('./systems/Root'));
const Individuals = lazy(() => import('./Individuals'));
const RootIndividual = lazy(() => import('./individuals/Root'));

const Root = () => {
  const redirect = useFirstVisiblePath(sectionEntries('entities'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/sectors"
          element={(
            <EntryGuard path="/dashboard/entities/sectors">
              {boundaryWrapper(Sectors)}
            </EntryGuard>
          )}
        />
        <Route
          path="/sectors/:sectorId/*"
          element={(
            <EntryGuard path="/dashboard/entities/sectors">
              {boundaryWrapper(RootSector)}
            </EntryGuard>
          )}
        />
        <Route
          path="/events"
          element={(
            <EntryGuard path="/dashboard/entities/events">
              {boundaryWrapper(Events)}
            </EntryGuard>
          )}
        />
        <Route
          path="/events/:eventId/*"
          element={(
            <EntryGuard path="/dashboard/entities/events">
              {boundaryWrapper(RootEvent)}
            </EntryGuard>
          )}
        />
        <Route
          path="/organizations"
          element={(
            <EntryGuard path="/dashboard/entities/organizations">
              {boundaryWrapper(Organizations)}
            </EntryGuard>
          )}
        />
        <Route
          path="/organizations/:organizationId/*"
          element={(
            <EntryGuard path="/dashboard/entities/organizations">
              {boundaryWrapper(RootOrganization)}
            </EntryGuard>
          )}
        />
        <Route
          path="/security_platforms"
          element={(
            <EntryGuard path="/dashboard/entities/security_platforms">
              {boundaryWrapper(Security)}
            </EntryGuard>
          )}
        />
        <Route
          path="/security_platforms/:securityPlatformId/*"
          element={(
            <EntryGuard path="/dashboard/entities/security_platforms">
              {boundaryWrapper(RootSecurity)}
            </EntryGuard>
          )}
        />
        <Route
          path="/systems"
          element={(
            <EntryGuard path="/dashboard/entities/systems">
              {boundaryWrapper(Systems)}
            </EntryGuard>
          )}
        />
        <Route
          path="/systems/:systemId/*"
          element={(
            <EntryGuard path="/dashboard/entities/systems">
              {boundaryWrapper(RootSystem)}
            </EntryGuard>
          )}
        />
        <Route
          path="/individuals"
          element={(
            <EntryGuard path="/dashboard/entities/individuals">
              {boundaryWrapper(Individuals)}
            </EntryGuard>
          )}
        />
        <Route
          path="/individuals/:individualId/*"
          element={(
            <EntryGuard path="/dashboard/entities/individuals">
              {boundaryWrapper(RootIndividual)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
