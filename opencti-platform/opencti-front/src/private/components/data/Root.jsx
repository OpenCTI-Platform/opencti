import React, { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import useHelper from '../../../utils/hooks/useHelper';
import { boundaryWrapper } from '../Error';
import useGranted, {
  BYPASS,
  CSVMAPPERS,
  INGESTION,
  INGESTION_SETINGESTIONS,
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
  KNOWLEDGE_KNUPDATE,
  MODULES,
  SETTINGS_SETACCESSES,
  TAXIIAPI,
} from '../../../utils/hooks/useGranted';
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
const Management = lazy(() => import('./Management'));

const Root = () => {
  const { isFeatureEnable } = useHelper();
  const isRightMenuManagementEnable = isFeatureEnable('DATA_MANAGEMENT_RIGHT_MENU');
  const isNewManagementScreenEnable = isFeatureEnable('MANAGE_RESTRICTED_ENTITIES');

  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const isGrantedToIngestion = useGranted([MODULES, INGESTION, INGESTION_SETINGESTIONS]);
  const isGrantedToImport = useGranted([KNOWLEDGE_KNASKIMPORT]);
  const isGrantedToProcessing = useGranted([KNOWLEDGE_KNUPDATE, SETTINGS_SETACCESSES, CSVMAPPERS]);
  const isGrantedToSharing = useGranted([TAXIIAPI]);
  const isGrantedToManage = useGranted([BYPASS]);

  let redirect = null;
  if (isGrantedToKnowledge) {
    redirect = 'entities';
  } else if (isGrantedToIngestion) {
    redirect = 'ingestion';
  } else if (isGrantedToImport) {
    redirect = 'import';
  } else if (isGrantedToProcessing) {
    redirect = 'processing';
  } else if (isGrantedToSharing) {
    redirect = 'sharing';
  } else if (isGrantedToManage) {
    redirect = 'restriction';
  }

  const isConnectorReader = useGranted([MODULES]);

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
              <Navigate to={isConnectorReader ? '/dashboard/data/ingestion/connectors' : '/dashboard/data/ingestion/sync'} />
            </Security>
          }
        />
        <Route
          path="/ingestion/sync"
          element={boundaryWrapper(Sync)}
        />
        <Route
          path="/ingestion/rss"
          element={boundaryWrapper(IngestionRss)}
        />
        <Route
          path="/ingestion/taxii"
          element={boundaryWrapper(IngestionTaxiis)}
        />
        <Route
          path="/ingestion/csv"
          element={boundaryWrapper(IngestionCsv)}
        />
        <Route
          path="/ingestion/connectors"
          element={boundaryWrapper(Connectors)}
        />
        <Route
          path="/ingestion/connectors/:connectorId"
          element={<RootConnector />}
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
          element={boundaryWrapper(Playbooks)}
        />
        <Route
          path="/processing/automation/:playbookId"
          element={boundaryWrapper(RootPlaybook)}
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
        {isRightMenuManagementEnable && (
        <Route
          path="/restriction"
          element={<Navigate to="/dashboard/data/restriction/restricted" replace={true} />}
        />
        )}
        {isNewManagementScreenEnable && (
        <Route
          path="/restriction/*"
          element={boundaryWrapper(Management)}
        />
        )}
      </Routes>
    </Suspense>
  );
};

export default Root;
