import React, { lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import { EXPLORE, EXPLORE_EXUPDATE, INVESTIGATION, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';

const Root = () => (
  <Routes>
    <Route
      path="/dashboards/*"
      element={
        <Security needs={[EXPLORE]}>
          <Workspaces type={'dashboard'} />
        </Security>
      }
    />
    <Route
      path="/dashboards/:workspaceId/*"
      element={
        <Security needs={[EXPLORE]}>
          <RootDashboard />
        </Security>
      }
    />
    <Route
      path="/investigations/*"
      element={
        <Security needs={[INVESTIGATION]}>
          <Workspaces type={'investigation'} />
        </Security>
      }
    />
    <Route
      path="/investigations/:workspaceId/*"
      element={
        <Security needs={[INVESTIGATION]}>
          <RootInvestigation />
        </Security>
      }
    />
  </Routes>
);

export default Root;
