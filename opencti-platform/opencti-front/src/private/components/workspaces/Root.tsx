import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import Workspaces from './Workspaces';
import RootDashboard from './dashboards/Root';
import RootInvestigation from './investigations/Root';
import { EXPLORE, INVESTIGATION } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import PublicDashboard from './dashboards/public_dashboards/PublicDashboards';
import RessaDWM from './dashboards/ressa_dwm/RessaDWM';
import OrganizationManagerDashboard from './dashboards/organization_manager_dashboard/OrganizationManagerDashboard';
import MiddleManagersDashboard from './dashboards/middle_managers_dashboard/MiddleManagersDashboard';
import OperationalManagersDashboard from './dashboards/operational_managers_dashboard/OperationalManagersDashboard';

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

const RessaDWMRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <RessaDWM />
  </Security>
);

const OrganizationManagerDashboardRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <OrganizationManagerDashboard />
  </Security>
);

const MiddleManagersDashboardRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <MiddleManagersDashboard />
  </Security>
);

const OperationalManagersDashboardRoute = () => (
  <Security needs={[EXPLORE]} placeholder={<Navigate to="/dashboard" />}>
    <OperationalManagersDashboard />
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
      path="/dashboards_ressa_dwm/*"
      element={<RessaDWMRoute />}
    />
    <Route
      path="/dashboards_organization_manager/*"
      element={<OrganizationManagerDashboardRoute />}
    />
    <Route
      path="/dashboards_middle_managers/*"
      element={<MiddleManagersDashboardRoute />}
    />
    <Route
      path="/dashboards_operational_managers/*"
      element={<OperationalManagersDashboardRoute />}
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
