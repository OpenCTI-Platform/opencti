import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';

const DeployCustomDashboards = lazy(() => import('./DeployCustomDashboard'));
const DeployCsvFeed = lazy(() => import('./DeployCsvFeed'));

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
          element={boundaryWrapper(DeployCsvFeed)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
