import React, { lazy, Suspense } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router';
import { boundaryWrapper } from '../Error';
import EntryGuard from '../nav/EntryGuard';
import useFirstVisiblePath from '../common/menus/useFirstVisiblePath';
import { sectionEntries } from '../nav/navSections';
import { entriesUnder } from '../nav/menuEntries';
import { integrations } from '../integrations/Integrations.entries';
import Loader from '../../../components/Loader';

const CsvMappers = lazy(() => import('./CsvMappers'));
const JsonMappers = lazy(() => import('./JsonMappers'));
const Entities = lazy(() => import('./Entities'));
const Relationships = lazy(() => import('./Relationships'));
const Tasks = lazy(() => import('./Tasks'));
const Taxii = lazy(() => import('./Taxii'));
const Stream = lazy(() => import('./Stream'));
const Feed = lazy(() => import('./Feed'));
const Playbooks = lazy(() => import('./Playbooks'));
const RootPlaybook = lazy(() => import('./playbooks/Root'));
const RootImport = lazy(() => import('./import/Root'));
const Management = lazy(() => import('./restriction/Root'));
const Health = lazy(() => import('./health/Root'));

// Legacy /dashboard/data/ingestion/* URLs redirect to the Integrations
// section, preserving any query params of the deep link.
const LegacyConnectorRedirect = () => {
  const { connectorId } = useParams();
  return <Navigate to={{ pathname: `/dashboard/integrations/connectors/${connectorId}`, search: window.location.search }} replace={true} />;
};

const LegacyCatalogConnectorRedirect = () => {
  const { connectorSlug } = useParams();
  return <Navigate to={{ pathname: `/dashboard/integrations/catalog/${connectorSlug}`, search: window.location.search }} replace={true} />;
};

const LegacyFormRedirect = () => {
  const { formId } = useParams();
  return <Navigate to={{ pathname: `/dashboard/integrations/feeds/form/${formId}`, search: window.location.search }} replace={true} />;
};

// Ingestion-only users have no Data page anymore: the ingestion section moved to the top-level Integrations menu.
const dataEntries = [...sectionEntries('data'), integrations];

const Root = () => {
  const redirect = useFirstVisiblePath(dataEntries);
  const processingRedirect = useFirstVisiblePath(entriesUnder('/dashboard/data/processing'));
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={redirect} replace={true} />}
        />
        <Route
          path="/entities"
          element={(
            <EntryGuard path="/dashboard/data/entities">
              {boundaryWrapper(Entities)}
            </EntryGuard>
          )}
        />
        <Route
          path="/relationships"
          element={(
            <EntryGuard path="/dashboard/data/relationships">
              {boundaryWrapper(Relationships)}
            </EntryGuard>
          )}
        />
        <Route
          path="/ingestion"
          element={<Navigate to="/dashboard/integrations" replace={true} />}
        />
        <Route
          path="/ingestion/sync"
          element={<Navigate to="/dashboard/integrations/deployed?kind=sync" replace={true} />}
        />
        <Route
          path="/ingestion/rss"
          element={<Navigate to="/dashboard/integrations/deployed?kind=rss" replace={true} />}
        />
        <Route
          path="/ingestion/taxii"
          element={<Navigate to="/dashboard/integrations/deployed?kind=taxii" replace={true} />}
        />
        <Route
          path="/ingestion/catalog"
          element={<Navigate to="/dashboard/integrations/available" replace={true} />}
        />
        <Route
          path="/ingestion/catalog/:connectorSlug"
          element={<LegacyCatalogConnectorRedirect />}
        />
        <Route
          path="/ingestion/collection"
          element={<Navigate to="/dashboard/integrations/deployed?kind=taxii-push" replace={true} />}
        />
        <Route
          path="/ingestion/csv"
          element={<Navigate to="/dashboard/integrations/deployed?kind=csv" replace={true} />}
        />
        <Route
          path="/ingestion/json"
          element={<Navigate to="/dashboard/integrations/deployed?kind=json" replace={true} />}
        />
        <Route
          path="/ingestion/forms"
          element={<Navigate to="/dashboard/integrations/deployed?kind=form" replace={true} />}
        />
        <Route
          path="/ingestion/forms/:formId"
          element={<LegacyFormRedirect />}
        />
        <Route
          path="/ingestion/connectors"
          element={<Navigate to="/dashboard/integrations/deployed" replace={true} />}
        />
        <Route
          path="/ingestion/connectors/:connectorId/*"
          element={<LegacyConnectorRedirect />}
        />
        <Route
          path="/import/*"
          element={(
            <EntryGuard path="/dashboard/data/import">
              {boundaryWrapper(RootImport)}
            </EntryGuard>
          )}
        />
        <Route
          path="/sharing"
          element={<Navigate to="/dashboard/data/sharing/streams" replace={true} />}
        />
        <Route
          path="/sharing/streams"
          element={(
            <EntryGuard path="/dashboard/data/sharing/streams">
              {boundaryWrapper(Stream)}
            </EntryGuard>
          )}
        />
        <Route
          path="/sharing/feeds"
          element={(
            <EntryGuard path="/dashboard/data/sharing/feeds">
              {boundaryWrapper(Feed)}
            </EntryGuard>
          )}
        />
        <Route
          path="/sharing/taxii"
          element={(
            <EntryGuard path="/dashboard/data/sharing/taxii">
              {boundaryWrapper(Taxii)}
            </EntryGuard>
          )}
        />
        <Route
          path="/processing"
          element={<Navigate to={processingRedirect} replace={true} />}
        />
        <Route
          path="/processing/automation"
          element={(
            <EntryGuard path="/dashboard/data/processing/automation">
              {boundaryWrapper(Playbooks)}
            </EntryGuard>
          )}
        />
        <Route
          path="/processing/automation/:playbookId"
          element={(
            <EntryGuard path="/dashboard/data/processing/automation">
              {boundaryWrapper(RootPlaybook)}
            </EntryGuard>
          )}
        />
        <Route
          path="/processing/csv_mapper"
          element={(
            <EntryGuard path="/dashboard/data/processing/csv_mapper">
              <CsvMappers />
            </EntryGuard>
          )}
        />
        <Route
          path="/processing/json_mapper"
          element={(
            <EntryGuard path="/dashboard/data/processing/json_mapper">
              <JsonMappers />
            </EntryGuard>
          )}
        />
        <Route
          path="/processing/tasks"
          element={(
            <EntryGuard path="/dashboard/data/processing/tasks">
              <Tasks />
            </EntryGuard>
          )}
        />
        <Route
          path="/restriction/*"
          element={(
            <EntryGuard path="/dashboard/data/restriction">
              {boundaryWrapper(Management)}
            </EntryGuard>
          )}
        />
        <Route
          path="/health/*"
          element={(
            <EntryGuard path="/dashboard/data/health">
              {boundaryWrapper(Health)}
            </EntryGuard>
          )}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
