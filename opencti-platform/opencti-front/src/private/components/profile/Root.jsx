import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import Notifications from './Notifications';
import Profile from './Profile';
import Triggers from './Triggers';
import Alerts from './Alerts';
import NewsFeed from './NewsFeed';

const Root = () => (
  <Routes>
    <Route
      path="/"
      element={<Navigate to="/dashboard/profile/me" replace={true} />}
    />
    <Route
      path="/me"
      element={<Profile />}
    />
    <Route
      path="/notifications"
      element={boundaryWrapper(Notifications)}
    >
      <Route index element={<Navigate to="alerts" replace={true} />} />
      <Route path="alerts" element={boundaryWrapper(Alerts)} />
      <Route path="news-feed" element={boundaryWrapper(NewsFeed)} />
    </Route>
    <Route
      path="/triggers"
      element={boundaryWrapper(Triggers)}
    />
  </Routes>
);

export default Root;
