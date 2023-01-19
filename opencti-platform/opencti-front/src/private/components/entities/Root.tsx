/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Sectors from './Sectors';
import RootSector from './sectors/Root';
import Events from './Events';
import RootEvent from './events/Root';
import Organizations from './Organizations';
import RootOrganization from './organizations/Root';
import Systems from './Systems';
import RootSystem from './systems/Root';
import Individuals from './Individuals';
import RootIndividual from './individuals/Root';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

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
  );
};

export default Root;
