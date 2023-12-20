/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { Suspense, lazy } from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
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
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/entities"
          render={() => <Redirect to={`/dashboard/entities/${redirect}`} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/sectors"
          component={Sectors}
        />
        <BoundaryRoute
          path="/dashboard/entities/sectors/:sectorId"
          component={RootSector}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/events"
          component={Events}
        />
        <BoundaryRoute
          path="/dashboard/entities/events/:eventId"
          component={RootEvent}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/organizations"
          component={Organizations}
        />
        <BoundaryRoute
          path="/dashboard/entities/organizations/:organizationId"
          component={RootOrganization}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/systems"
          component={Systems}
        />
        <BoundaryRoute
          path="/dashboard/entities/systems/:systemId"
          component={RootSystem}
        />
        <BoundaryRoute
          exact
          path="/dashboard/entities/individuals"
          component={Individuals}
        />
        <BoundaryRoute
          path="/dashboard/entities/individuals/:individualId"
          component={RootIndividual}
        />
      </Switch>
    </Suspense>
  );
};

export default Root;
