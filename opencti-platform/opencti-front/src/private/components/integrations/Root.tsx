import React, { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import { APP_MODULE } from '../../../utils/logs/errorOrigin';
import Loader from '../../../components/Loader';

const Integrations = lazy(() => import('./Integrations'));
const RootConnector = lazy(() => import('@components/data/connectors/Root'));
const IngestionCatalogConnector = lazy(() => import('./catalog/IngestionCatalogConnector'));
const FeedDetail = lazy(() => import('./feeds/FeedDetail'));

const Root = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to="/dashboard/integrations/deployed" replace={true} />}
        />
        {/* Generic entity links (resolveLink) target the connectors base URL:
            the deployed tab is the connectors landing view. */}
        <Route
          path="/connectors"
          element={<Navigate to="/dashboard/integrations/deployed" replace={true} />}
        />
        <Route
          path="/connectors/:connectorId/*"
          element={<RootConnector />}
        />
        <Route
          path="/catalog"
          element={<Navigate to="/dashboard/integrations/available" replace={true} />}
        />
        <Route
          path="/catalog/:connectorSlug"
          element={boundaryWrapper(IngestionCatalogConnector, APP_MODULE.CATALOG)}
        />
        <Route
          path="/feeds/:feedKind/:feedId"
          element={boundaryWrapper(FeedDetail)}
        />
        <Route
          path="/:tab"
          element={boundaryWrapper(Integrations)}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
