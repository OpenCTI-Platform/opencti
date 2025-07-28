import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';

const DeployCustomDashboards = lazy(() => import('./DeployCustomDashboard'));
const DeployIntegrationFeed = lazy(() => import('./DeployIntegrationFeed'));

const Root = () => {
  return (
    <Suspense>
      <Routes>
        <Route
          path="/deploy-custom-dashboard/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployCustomDashboards)}
        />
        <Route
          path="/deploy-integration-feed/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployIntegrationFeed)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
