import React from 'react';
import { Route, Routes } from 'react-router';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import EntryGuard from '../nav/EntryGuard';
import PublicDashboard from './dashboards/public_dashboards/PublicDashboards';

const DashboardRoute = () => (
  <EntryGuard path="/dashboard/workspaces/dashboards">
    <Workspaces type="dashboard" />
  </EntryGuard>
);

const DashboardWorkspaceRoute = () => (
  <EntryGuard path="/dashboard/workspaces/dashboards">
    <RootDashboard />
  </EntryGuard>
);

const PublicDashboardRoute = () => (
  <EntryGuard path="/dashboard/workspaces/dashboards_public">
    <PublicDashboard />
  </EntryGuard>
);

const InvestigationRoute = () => (
  <EntryGuard path="/dashboard/workspaces/investigations">
    <Workspaces type="investigation" />
  </EntryGuard>
);

const InvestigationWorkspaceRoute = () => (
  <EntryGuard path="/dashboard/workspaces/investigations">
    <RootInvestigation />
  </EntryGuard>
);

const Root = () => (
  <Routes>
    <Route
      path="/dashboards/*"
      element={<DashboardRoute />}
    />
    <Route
      path="/dashboards/:workspaceId/*"
      element={<DashboardWorkspaceRoute />}
    />
    <Route
      path="/dashboards_public/*"
      element={<PublicDashboardRoute />}
    />
    <Route
      path="/investigations/*"
      element={<InvestigationRoute />}
    />
    <Route
      path="/investigations/:workspaceId/*"
      element={<InvestigationWorkspaceRoute />}
    />
  </Routes>
);

export default Root;
