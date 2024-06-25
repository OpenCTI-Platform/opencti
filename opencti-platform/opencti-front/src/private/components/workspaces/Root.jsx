import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import { EXPLORE, INVESTIGATION } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const Root = () => (
  <Routes>
    <Route
      path="/dashboards/*"
      element={
        <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
          <Workspaces type={'dashboard'} />
        </Security>
      }
    />
    <Route
      path="/dashboards/:workspaceId/*"
      element={
        <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
          <RootDashboard />
        </Security>
      }
    />
    <Route
      path="/investigations/*"
      element={
        <Security needs={[INVESTIGATION]} placeholder={<Navigate to="/dashboard" />}>
          <Workspaces type={'investigation'} />
        </Security>
      }
    />
    <Route
      path="/investigations/:workspaceId/*"
      element={
        <Security needs={[INVESTIGATION]} placeholder={<Navigate to="/dashboard" />}>
          <RootInvestigation />
        </Security>
      }
    />
  </Routes>
);

export default Root;
