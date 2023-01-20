import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Triggers from './Triggers';
import Notifications from './Notifications';
import Profile from './Profile';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/profile"
      render={() => <Redirect to="/dashboard/profile/me" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/profile/me"
      render={(routeProps) => <Profile {...routeProps} />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/profile/notifications"
      component={Notifications}
    />
    <BoundaryRoute
      exact
      path="/dashboard/profile/triggers"
      component={Triggers}
    />
  </Switch>
);

export default Root;
