import React from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import Notifications from './Notifications';
import Profile from './Profile';
import Triggers from './Triggers';

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
    />
    {/* Legacy nested paths from before the news feed page extraction: keep bookmarks working. */}
    <Route
      path="/notifications/alerts"
      element={<Navigate to="/dashboard/profile/notifications" replace={true} />}
    />
    <Route
      path="/notifications/news-feed"
      element={<Navigate to="/dashboard/news-feed" replace={true} />}
    />
    <Route
      path="/triggers"
      element={boundaryWrapper(Triggers)}
    />
  </Routes>
);

export default Root;
