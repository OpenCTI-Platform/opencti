import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
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

class Root extends Component {
  render() {
    const { me } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => {
          let redirect = null;
          if (!helper.isEntityTypeHidden('Sector')) {
            redirect = 'sectors';
          } else if (!helper.isEntityTypeHidden('Event')) {
            redirect = 'events';
          } else if (!helper.isEntityTypeHidden('Organization')) {
            redirect = 'organizations';
          } else if (!helper.isEntityTypeHidden('System')) {
            redirect = 'systems';
          }
          return (
            <Switch>
              <BoundaryRoute
                exact
                path="/dashboard/entities"
                render={() => (
                  <Redirect to={`/dashboard/entities/${redirect}`} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/entities/sectors"
                component={Sectors}
              />
              <BoundaryRoute
                path="/dashboard/entities/sectors/:sectorId"
                render={(routeProps) => <RootSector {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/entities/events"
                component={Events}
              />
              <BoundaryRoute
                path="/dashboard/entities/events/:eventId"
                render={(routeProps) => <RootEvent {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/entities/organizations"
                component={Organizations}
              />
              <BoundaryRoute
                path="/dashboard/entities/organizations/:organizationId"
                render={(routeProps) => (
                  <RootOrganization {...routeProps} me={me} />
                )}
              />
              <BoundaryRoute
                exact
                path="/dashboard/entities/systems"
                component={Systems}
              />
              <BoundaryRoute
                path="/dashboard/entities/systems/:systemId"
                render={(routeProps) => <RootSystem {...routeProps} me={me} />}
              />
              <BoundaryRoute
                exact
                path="/dashboard/entities/individuals"
                component={Individuals}
              />
              <BoundaryRoute
                path="/dashboard/entities/individuals/:individualId"
                render={(routeProps) => (
                  <RootIndividual {...routeProps} me={me} />
                )}
              />
            </Switch>
          );
        }}
      </UserContext.Consumer>
    );
  }
}

Root.propTypes = {
  me: PropTypes.object,
};

export default Root;
