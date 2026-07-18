import React, { lazy, Suspense } from 'react';
import { Navigate, Route, Routes, useParams } from 'react-router-dom';
import { boundaryWrapper } from '../Error';
import useGranted, { AUTOMATION_AUTMANAGE, BYPASS, CSVMAPPERS, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT, KNOWLEDGE_KNUPDATE, TAXIIAPI } from '../../../utils/hooks/useGranted';
import useHelper from '../../../utils/hooks/useHelper';
import Loader from '../../../components/Loader';

const CsvMappers = lazy(() => import('./CsvMappers'));
const JsonMappers = lazy(() => import('./JsonMappers'));
const Security = lazy(() => import('../../../utils/Security'));
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

// Legacy /dashboard/data/ingestion/* URLs redirect to the Integrations section.
const LegacyConnectorRedirect = () => {
  const { connectorId } = useParams();
  return <Navigate to={`/dashboard/integrations/connectors/${connectorId}`} replace={true} />;
};

const LegacyCatalogConnectorRedirect = () => {
  const { connectorSlug } = useParams();
  return <Navigate to={{ pathname: `/dashboard/integrations/catalog/${connectorSlug}`, search: window.location.search }} replace={true} />;
};

const LegacyFormRedirect = () => {
  const { formId } = useParams();
  return <Navigate to={`/dashboard/integrations/feeds/form/${formId}`} replace={true} />;
};

const Root = () => {
  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const isGrantedToImport = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const isGrantedToProcessing = useGranted([KNOWLEDGE_KNUPDATE, CSVMAPPERS, AUTOMATION_AUTMANAGE]);
  const isGrantedToSharing = useGranted([TAXIIAPI]);
  const isGrantedToManage = useGranted([BYPASS]);

  let redirect: string | null = null;
  if (isGrantedToKnowledge) {
    redirect = 'entities';
  } else if (isGrantedToImport) {
    redirect = 'import';
  } else if (isGrantedToProcessing) {
    redirect = 'processing';
  } else if (isGrantedToSharing) {
    redirect = 'sharing';
  } else if (isGrantedToManage) {
    redirect = 'restriction';
  }

  const isGrantedToAutomation = useGranted([AUTOMATION_AUTMANAGE]);
  const { isFeatureEnable } = useHelper();
  const isDataSanityManagerEnabled = isFeatureEnable('DATA_SANITY_MANAGER');
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/data/${redirect}`} replace={true} />}
        />
        <Route
          path="/entities"
          element={boundaryWrapper(Entities)}
        />
        <Route
          path="/relationships"
          element={boundaryWrapper(Relationships)}
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
          element={boundaryWrapper(RootImport)}
        />
        <Route
          path="/sharing"
          element={<Navigate to="/dashboard/data/sharing/streams" replace={true} />}
        />
        <Route
          path="/sharing/streams"
          element={boundaryWrapper(Stream)}
        />
        <Route
          path="/sharing/feeds"
          element={boundaryWrapper(Feed)}
        />
        <Route
          path="/sharing/taxii"
          element={boundaryWrapper(Taxii)}
        />
        <Route
          path="/processing"
          element={(
            <Security
              needs={[KNOWLEDGE_KNUPDATE, AUTOMATION_AUTMANAGE]}
              placeholder={(
                <Security
                  needs={[CSVMAPPERS]}
                  placeholder={<Navigate to="/dashboard/data/processing/tasks" />}
                >
                  <Navigate to="/dashboard/data/processing/csv_mapper" />
                </Security>
              )}
            >
              <Navigate to={isGrantedToAutomation ? '/dashboard/data/processing/automation' : '/dashboard/data/processing/tasks'} />
            </Security>
          )}
        />
        <Route
          path="/processing/automation"
          element={boundaryWrapper(Playbooks)}
        />
        <Route
          path="/processing/automation/:playbookId"
          element={boundaryWrapper(RootPlaybook)}
        />
        <Route
          path="/processing/csv_mapper"
          element={(
            <Security
              needs={[CSVMAPPERS]}
              placeholder={<Navigate to="/dashboard" />}
            >
              <CsvMappers />
            </Security>
          )}
        />
        <Route
          path="/processing/json_mapper"
          element={(
            <Security
              needs={[CSVMAPPERS]}
              placeholder={<Navigate to="/dashboard" />}
            >
              <JsonMappers />
            </Security>
          )}
        />
        <Route
          path="/processing/tasks"
          element={(
            <Security
              needs={[KNOWLEDGE_KNUPDATE]}
              placeholder={<Navigate to="/dashboard" />}
            >
              <Tasks />
            </Security>
          )}
        />
        <Route
          path="/restriction/*"
          element={boundaryWrapper(Management)}
        />
        <Route
          path="/health/*"
          element={isDataSanityManagerEnabled ? boundaryWrapper(Health) : <Navigate to="/dashboard" />}
        />
      </Routes>
    </Suspense>
  );
};

export default Root;
