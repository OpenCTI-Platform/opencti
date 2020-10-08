import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Connectors from './Connectors';
import Curation from './Curation';
import { BoundaryRoute } from '../Error';
import RootConnector from './connectors/Root';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/data"
      render={() => <Redirect to="/dashboard/data/connectors" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/data/connectors"
      component={Connectors}
    />
    <BoundaryRoute
      path="/dashboard/data/connectors/:connectorId"
      render={(routeProps) => <RootConnector {...routeProps} />}
    />
    <BoundaryRoute exact path="/dashboard/data/curation" component={Curation} />
  </Switch>
);

export default Root;
