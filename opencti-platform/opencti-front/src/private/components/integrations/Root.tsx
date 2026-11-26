import React, { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router';
import { boundaryWrapper } from '../Error';
import { APP_MODULE } from '../../../utils/logging/errorOrigin';
import Loader from '../../../components/Loader';
import EntryGuard from '../nav/EntryGuard';

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
          element={(
            <EntryGuard path="/dashboard/integrations">
              <RootConnector />
            </EntryGuard>
          )}
        />
        <Route
          path="/catalog"
          element={<Navigate to="/dashboard/integrations/available" replace={true} />}
        />
        <Route
          path="/catalog/:connectorSlug"
          element={(
            <EntryGuard path="/dashboard/integrations">
              {boundaryWrapper(IngestionCatalogConnector, APP_MODULE.CATALOG)}
            </EntryGuard>
          )}
        />
        <Route
          path="/feeds/:feedKind/:feedId"
          element={(
            <EntryGuard path="/dashboard/integrations">
              {boundaryWrapper(FeedDetail)}
            </EntryGuard>
          )}
        />
        <Route
          path="/:tab"
          element={(
            <EntryGuard path="/dashboard/integrations">
              {boundaryWrapper(Integrations)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
