import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Connectors from './Connectors';
import Entities from './Entities';
import Relationships from './Relationships';
import Tasks from './Tasks';
import Taxii from './Taxii';
import { BoundaryRoute } from '../Error';
import RootConnector from './connectors/Root';
import Stream from './Stream';
import Feed from './Feed';
import Sync from './Sync';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/data"
      render={() => <Redirect to="/dashboard/data/entities" />}
    />
    <BoundaryRoute exact path="/dashboard/data/entities" component={Entities} />
    <BoundaryRoute
      exact
      path="/dashboard/data/relationships"
      component={Relationships}
    />
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
    <BoundaryRoute exact path="/dashboard/data/sync" component={Sync} />
    <BoundaryRoute
      exact
      path="/dashboard/data/sharing"
      render={() => <Redirect to="/dashboard/data/sharing/streams" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/data/sharing/streams"
      component={Stream}
    />
    <BoundaryRoute
      exact
      path="/dashboard/data/sharing/feeds"
      component={Feed}
    />
    <BoundaryRoute
      exact
      path="/dashboard/data/sharing/taxii"
      component={Taxii}
    />
  </Switch>
);

export default Root;
