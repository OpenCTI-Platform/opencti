/* eslint-disable @typescript-eslint/no-explicit-any */
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
          element={ <Navigate to={`/dashboard/entities/${redirect}`} />}
        />
        <Route
          path="/sectors"
          Component={boundaryWrapper(Sectors)}
        />
        <Route
          path="/sectors/:sectorId/*"
          Component={boundaryWrapper(RootSector)}
        />
        <Route
          path="/events"
          Component={boundaryWrapper(Events)}
        />
        <Route
          path="/events/:eventId/*"
          Component={boundaryWrapper(RootEvent)}
        />
        <Route
          path="/organizations"
          Component={boundaryWrapper(Organizations)}
        />
        <Route
          path="/organizations/:organizationId/*"
          Component={boundaryWrapper(RootOrganization)}
        />
        <Route
          path="/systems"
          Component={boundaryWrapper(Systems)}
        />
        <Route
          path="/systems/:systemId/*"
          Component={boundaryWrapper(RootSystem)}
        />
        <Route
          path="/individuals"
          Component={boundaryWrapper(Individuals)}
        />
        <Route
          path="/individuals/:individualId/*"
          Component={boundaryWrapper(RootIndividual)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
