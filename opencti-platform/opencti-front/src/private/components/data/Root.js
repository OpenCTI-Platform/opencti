import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Connectors from './Connectors';
import Entities from './Entities';
import Tasks from './Tasks';
import Taxii from './Taxii';
import { BoundaryRoute } from '../Error';
import RootConnector from './connectors/Root';
import Stream from './Stream';
import Sync from './Sync';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/data"
      render={() => <Redirect to="/dashboard/data/entities" />}
    />
    <BoundaryRoute exact path="/dashboard/data/entities" component={Entities} />
    <BoundaryRoute exact path="/dashboard/data/tasks" component={Tasks} />
    <BoundaryRoute
      exact
      path="/dashboard/data/connectors"
      component={Connectors}
    />
    <BoundaryRoute
      path="/dashboard/data/connectors/:connectorId"
      render={(routeProps) => <RootConnector {...routeProps} />}
    />
    <BoundaryRoute exact path="/dashboard/data/taxii" component={Taxii} />
    <BoundaryRoute exact path="/dashboard/data/stream" component={Stream} />
    <BoundaryRoute exact path="/dashboard/data/sync" component={Sync} />
  </Switch>
);

export default Root;
