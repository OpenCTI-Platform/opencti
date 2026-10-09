import React from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router';
import { boundaryWrapper } from '../Error';
import Notifications from './Notifications';
import Profile from './Profile';

const Root = () => {
  const location = useLocation();

  return (
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
        path="/notifications/*"
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
        element={(
          <Navigate
            to={{
              pathname: '/dashboard/profile/notifications/triggers',
              search: location.search,
              hash: location.hash,
            }}
            replace={true}
          />
        )}
      />
    </Routes>
  );
};

export default Root;
