import React from 'react';
import { Switch } from 'react-router-dom';
import Dashboards from './Dashboards';
import RootDashboard from './dashboards/Root';
import { BoundaryRoute } from '../Error';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/workspaces/dashboards"
      component={Dashboards}
    />
    <BoundaryRoute
      path="/dashboard/workspaces/dashboards/:workspaceId"
      render={(routeProps) => <RootDashboard {...routeProps} />}
    />
  </Switch>
);

export default Root;
