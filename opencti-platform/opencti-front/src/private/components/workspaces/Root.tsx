import React from 'react';
import { Navigate, Route, Routes } from 'react-router';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import { EXPLORE, INVESTIGATION } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import PublicDashboard from './dashboards/public_dashboards/PublicDashboards';

const DashboardRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <Workspaces type="dashboard" />
  </Security>
);

const DashboardWorkspaceRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <RootDashboard />
  </Security>
);

const PublicDashboardRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <PublicDashboard />
  </Security>
);

const InvestigationRoute = () => (
  <Security needs={[INVESTIGATION]} placeholder={<Navigate to="/dashboard" />}>
    <Workspaces type="investigation" />
  </Security>
);

const InvestigationWorkspaceRoute = () => (
  <Security needs={[INVESTIGATION]} placeholder={<Navigate to="/dashboard" />}>
    <RootInvestigation />
  </Security>
);

const Root = () => (
  <Routes>
    <Route path="/dashboards">
      <Route index element={<DashboardRoute />} />
      <Route path=":workspaceId">
        <Route path="*" index element={<DashboardWorkspaceRoute />} />
      </Route>
    </Route>
    <Route path="/dashboards_public">
      <Route index element={<PublicDashboardRoute />} />
    </Route>
    <Route path="/investigations">
      <Route index element={<InvestigationRoute />} />
      <Route path=":workspaceId">
        <Route path="*" index element={<InvestigationWorkspaceRoute />} />
      </Route>
    </Route>
  </Routes>
);

export default Root;
