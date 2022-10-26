import React from 'react';
import { Switch } from 'react-router-dom';
import CyioDashboards from './CyioDashboards';
import Investigations from './Investigations';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import { BoundaryRoute } from '../Error';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/workspaces/dashboards"
      component={CyioDashboards}
    />
    <BoundaryRoute
      path="/dashboard/workspaces/dashboards/:workspaceId"
      render={(routeProps) => <RootDashboard {...routeProps} />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/workspaces/investigations"
      component={Investigations}
    />
    <BoundaryRoute
      path="/dashboard/workspaces/investigations/:workspaceId"
      render={(routeProps) => <RootInvestigation {...routeProps} />}
    />
  </Switch>
);

export default Root;
