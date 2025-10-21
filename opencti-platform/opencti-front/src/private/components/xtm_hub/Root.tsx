import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';

const DeployCustomDashboards = lazy(() => import('./DeployCustomDashboard'));
const IngestionCsv = lazy(() => import('../data/IngestionCsv'));

const Root = () => {
  return (
    <Suspense>
      <Routes>
        <Route
          path="/deploy-custom-dashboard/:serviceInstanceId/:fileId"
          element={boundaryWrapper(DeployCustomDashboards)}
        />
        <Route
          path="/deploy-csv-feed/:serviceInstanceId/:fileId"
          element={boundaryWrapper(IngestionCsv)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
