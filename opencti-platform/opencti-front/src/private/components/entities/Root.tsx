// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
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
  let redirect: string | null = null;
  if (!useIsHiddenEntity('Sector')) {
    redirect = 'sectors';
  } else if (!useIsHiddenEntity('Event')) {
    redirect = 'events';
  } else if (!useIsHiddenEntity('Organization')) {
    redirect = 'organizations';
  } else if (!useIsHiddenEntity('Security-Platform')) {
    redirect = 'security_platforms';
  } else if (!useIsHiddenEntity('System')) {
    redirect = 'systems';
  } else if (!useIsHiddenEntity('Individual')) {
    redirect = 'individuals';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/entities/${redirect}`} replace={true} />}
        />
        <Route
          path="/sectors"
          element={boundaryWrapper(Sectors)}
        />
        <Route
          path="/sectors/:sectorId/*"
          element={boundaryWrapper(RootSector)}
        />
        <Route
          path="/events"
          element={boundaryWrapper(Events)}
        />
        <Route
          path="/events/:eventId/*"
          element={boundaryWrapper(RootEvent)}
        />
        <Route
          path="/organizations"
          element={boundaryWrapper(Organizations)}
        />
        <Route
          path="/organizations/:organizationId/*"
          element={boundaryWrapper(RootOrganization)}
        />
        <Route
          path="/security_platforms"
          element={boundaryWrapper(Security)}
        />
        <Route
          path="/security_platforms/:securityPlatformId/*"
          element={boundaryWrapper(RootSecurity)}
        />
        <Route
          path="/systems"
          element={boundaryWrapper(Systems)}
        />
        <Route
          path="/systems/:systemId/*"
          element={boundaryWrapper(RootSystem)}
        />
        <Route
          path="/individuals"
          element={boundaryWrapper(Individuals)}
        />
        <Route
          path="/individuals/:individualId/*"
          element={boundaryWrapper(RootIndividual)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
