import React from 'react';
import { Redirect, Routes } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Notifications from './Notifications';
import Profile from './Profile';
import Triggers from './Triggers';

const Root = () => (
  <Routes>
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
  </Routes>
);

export default Root;
