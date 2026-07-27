import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';

const DeployCustomDashboards = lazy(() => import('./DeployCustomDashboard'));
const DeployCustomView = lazy(() => import('./DeployCustomView'));
const DeployPlaybook = lazy(() => import('./DeployPlaybook'));
const DeployBuiltInFeed = lazy(() => import('./DeployBuiltInFeed'));
const IngestionCatalogConnector = lazy(() => import('../integrations/catalog/IngestionCatalogConnector'));

const Root = () => {
  return (
    <Suspense>
      <Routes>
        <Route
          path="/deploy-custom-dashboard/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployCustomDashboards)}
        />
        <Route
          path="/deploy-custom-view/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployCustomView)}
        />
        <Route
          path="/deploy-playbook/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployPlaybook)}
        />
        <Route
          path="/deploy-csv-feed/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployBuiltInFeed)}
        />
        {/* OpenCTI streams */}
        <Route
          path="/deploy-sync/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployBuiltInFeed)}
        />
        {/* Query param: ?openConfig=true to auto-open deployment dialog */}
        <Route
          path="/deploy-connector/:connectorSlug"
          element={boundaryWrapper(IngestionCatalogConnector)}
        />
        <Route
          path="/deploy-taxii-feed/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployBuiltInFeed)}
        />
        <Route
          path="/deploy-rss-feed/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployBuiltInFeed)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
