// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router';
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
        <Route path="/sectors">
          <Route index element={boundaryWrapper(Sectors)} />
          <Route path=":sectorId">
            <Route path="*" index element={boundaryWrapper(RootSector)} />
          </Route>
        </Route>
        <Route path="/events">
          <Route index element={boundaryWrapper(Events)} />
          <Route path=":eventId">
            <Route path="*" index element={boundaryWrapper(RootEvent)} />
          </Route>
        </Route>
        <Route path="/organizations">
          <Route index element={boundaryWrapper(Organizations)} />
          <Route path=":organizationId">
            <Route path="*" index element={boundaryWrapper(RootOrganization)} />
          </Route>
        </Route>
        <Route path="/security_platforms">
          <Route index element={boundaryWrapper(Security)} />
          <Route path=":securityPlatformId">
            <Route path="*" index element={boundaryWrapper(RootSecurity)} />
          </Route>
        </Route>
        <Route path="/systems">
          <Route index element={boundaryWrapper(Systems)} />
          <Route path=":systemId">
            <Route path="*" index element={boundaryWrapper(RootSystem)} />
          </Route>
        </Route>
        <Route path="/individuals">
          <Route index element={boundaryWrapper(Individuals)} />
          <Route path=":individualId">
            <Route path="*" index element={boundaryWrapper(RootIndividual)} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
};

export default Root;
