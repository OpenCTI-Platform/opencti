import React from 'react';
import { Switch } from 'react-router-dom';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import { BoundaryRoute } from '../Error';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/workspaces/dashboards"
      render={() => <Workspaces type={'dashboard'} />}
    />
    <BoundaryRoute
      path="/dashboard/workspaces/dashboards/:workspaceId"
      render={(routeProps) => <RootDashboard {...routeProps} />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/workspaces/investigations"
      render={() => <Workspaces type={'investigation'} />}
    />
    <BoundaryRoute
      path="/dashboard/workspaces/investigations/:workspaceId"
      render={(routeProps) => <RootInvestigation {...routeProps} />}
    />
  </Switch>
);

export default Root;
