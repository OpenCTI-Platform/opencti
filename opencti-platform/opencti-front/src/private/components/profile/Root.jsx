import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import Notifications from './Notifications';
import Profile from './Profile';
import Triggers from './Triggers';

const Root = () => (
  <Routes>
    <Route
      path="/"
      element={<Navigate to="/dashboard/profile/me" />}
    />
    <Route
      path="/me"
      element={<Profile />}
    />
    <Route
      path="/notifications"
      Component={boundaryWrapper(Notifications)}
    />
    <Route
      path="/triggers"
      Component={boundaryWrapper(Triggers)}
    />
  </Routes>
);

export default Root;
