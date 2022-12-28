import React, { useContext } from 'react';
import { Switch, Redirect } from 'react-router-dom';
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
import { UserContext } from '../../../utils/hooks/useAuth';

const Root = () => {
  const { helper } = useContext(UserContext);
  let redirect = null;
  if (!helper.isEntityTypeHidden('Sector')) {
    redirect = 'sectors';
  } else if (!helper.isEntityTypeHidden('Event')) {
    redirect = 'events';
  } else if (!helper.isEntityTypeHidden('Organization')) {
    redirect = 'organizations';
  } else if (!helper.isEntityTypeHidden('System')) {
    redirect = 'systems';
  } else if (!helper.isEntityTypeHidden('Individual')) {
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
