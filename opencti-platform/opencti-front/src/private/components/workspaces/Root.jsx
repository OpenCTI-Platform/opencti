import React from 'react';
import { Route, Routes } from 'react-router-dom';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';

const Root = () => (
  <Routes>
    <Route
      path="/dashboards/*"
      element={<Workspaces type={'dashboard'} />}
    />
    <Route
      path="/dashboards/:workspaceId/*"
      element={<RootDashboard/>}
    />
    <Route
      path="/investigations/*"
      element={<Workspaces type={'investigation'} />}
    />
    <Route
      path="/investigations/:workspaceId/*"
      element={<RootInvestigation />}
    />
  </Routes>
);

export default Root;
