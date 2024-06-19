import React, { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import { KNOWLEDGE_KNUPDATE, MODULES, SETTINGS_SETACCESSES, INGESTION, CSVMAPPERS } from '../../../utils/hooks/useGranted';
import Loader from '../../../components/Loader';

const CsvMappers = lazy(() => import('./CsvMappers'));
const Security = lazy(() => import('../../../utils/Security'));
const Connectors = lazy(() => import('./Connectors'));
const IngestionCsv = lazy(() => import('./IngestionCsv'));
const Entities = lazy(() => import('./Entities'));
const Relationships = lazy(() => import('./Relationships'));
const Tasks = lazy(() => import('./Tasks'));
const Taxii = lazy(() => import('./Taxii'));
const RootConnector = lazy(() => import('./connectors/Root'));
const Stream = lazy(() => import('./Stream'));
const Feed = lazy(() => import('./Feed'));
const Sync = lazy(() => import('./Sync'));
const IngestionRss = lazy(() => import('./IngestionRss'));
const IngestionTaxiis = lazy(() => import('./IngestionTaxiis'));
const Playbooks = lazy(() => import('./Playbooks'));
const RootPlaybook = lazy(() => import('./playbooks/Root'));
const RootImport = lazy(() => import('./import/Root'));

const Root = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to="/dashboard/data/entities" replace={true} />}
        />
        <Route
          path="/entities"
          Component={boundaryWrapper(Entities)}
        />
        <Route
          path="/relationships"
          Component={boundaryWrapper(Relationships)}
        />
        <Route
          path="/ingestion"
          element={
            <Security
              needs={[INGESTION]}
              placeholder={(
                <Security
                  needs={[MODULES]}
                  placeholder={(
                    <Navigate to="/dashboard" />
                  )}
                >
                  <Navigate to="/dashboard/data/ingestion/connectors" />
                </Security>
              )}
            >
              <Navigate to="/dashboard/data/ingestion/sync" />
            </Security>
          }
        />
        <Route
          path="/ingestion/sync"
          Component={boundaryWrapper(Sync)}
        />
        <Route
          path="/ingestion/rss"
          Component={boundaryWrapper(IngestionRss)}
        />
        <Route
          path="/ingestion/taxii"
          Component={boundaryWrapper(IngestionTaxiis)}
        />
        <Route
          path="/ingestion/csv"
          Component={boundaryWrapper(IngestionCsv)}
        />
        <Route
          path="/ingestion/connectors"
          Component={boundaryWrapper(Connectors)}
        />
        <Route
          path="/ingestion/connectors/:connectorId"
          element={<RootConnector />}
        />
        <Route
          path="/import/*"
          Component={boundaryWrapper(RootImport)}
        />
        <Route
          path="/sharing"
          element={<Navigate to="/dashboard/data/sharing/streams" replace={true} />}
        />
        <Route
          path="/sharing/streams"
          Component={boundaryWrapper(Stream)}
        />
        <Route
          path="/sharing/feeds"
          Component={boundaryWrapper(Feed)}
        />
        <Route
          path="/sharing/taxii"
          Component={boundaryWrapper(Taxii)}
        />
        <Route
          path="/processing"
          element={
            <Security
              needs={[SETTINGS_SETACCESSES]}
              placeholder={(
                <Security
                  needs={[CSVMAPPERS]}
                  placeholder={<Navigate to="/dashboard/data/processing/tasks" />}
                >
                  <Navigate to="/dashboard/data/processing/csv_mapper" />
                </Security>
              )}
            >
              <Navigate to="/dashboard/data/processing/automation" />
            </Security>
          }
        />
        <Route
          path="/processing/automation"
          Component={boundaryWrapper(Playbooks)}
        />
        <Route
          path="/processing/automation/:playbookId"
          Component={boundaryWrapper(RootPlaybook)}
        />
        <Route
          path="/processing/csv_mapper"
          element={
            <Security
              needs={[CSVMAPPERS]}
              placeholder={<Navigate to="/dashboard" />}
            >
              <CsvMappers/>
            </Security>
          }
        />
        <Route
          path="/processing/tasks"
          element={
            <Security
              needs={[KNOWLEDGE_KNUPDATE]}
              placeholder={<Navigate to="/dashboard" />}
            >
              <Tasks />
            </Security>
          }
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
