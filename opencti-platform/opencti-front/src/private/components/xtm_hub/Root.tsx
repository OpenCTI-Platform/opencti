import React, { Suspense, lazy } from 'react';
import { Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';

const DeployCustomDashboards = lazy(() => import('./DeployCustomDashboard'));
const IngestionCsv = lazy(() => import('../data/IngestionCsv'));
const IngestionTaxii = lazy(() => import('../data/IngestionTaxiis'));
const IngestionCatalogConnector = lazy(() => import('../data/IngestionCatalog/IngestionCatalogConnector'));

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
        {/* Query param: ?openConfig=true to auto-open deployment dialog */}
        <Route
          path="/deploy-connector/:connectorSlug"
          element={boundaryWrapper(IngestionCatalogConnector)}
        />
        <Route
          path="/deploy-taxii-feed/:serviceInstanceId/:fileId"
          element={boundaryWrapper(IngestionTaxii)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
