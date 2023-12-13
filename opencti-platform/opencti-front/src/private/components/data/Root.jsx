import React, { Suspense, lazy } from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import { SETTINGS_SETACCESSES } from '../../../utils/hooks/useGranted';
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

const Root = () => {
  return (
    <Suspense fallback={<Loader />}>
      <Switch>
        <BoundaryRoute
          exact
          path="/dashboard/data"
          render={() => <Redirect to="/dashboard/data/entities" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/entities"
          component={Entities}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/relationships"
          component={Relationships}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/connectors"
          component={Connectors}
        />
        <BoundaryRoute
          path="/dashboard/data/connectors/:connectorId"
          render={(routeProps) => <RootConnector {...routeProps} />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/ingestion"
          render={() => <Redirect to="/dashboard/data/ingestion/sync" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/ingestion/sync"
          component={Sync}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/ingestion/rss"
          component={IngestionRss}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/ingestion/taxii"
          component={IngestionTaxiis}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/ingestion/csv"
          component={IngestionCsv}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/ingestion/csv"
          component={IngestionCsv}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/sharing"
          render={() => <Redirect to="/dashboard/data/sharing/streams" />}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/sharing/streams"
          component={Stream}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/sharing/feeds"
          component={Feed}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/sharing/taxii"
          component={Taxii}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/processing"
          render={() => (
            <Security
              needs={[SETTINGS_SETACCESSES]}
              placeholder={<Redirect to="/dashboard/data/processing/tasks" />}
            >
              <Redirect to="/dashboard/data/processing/automation" />
            </Security>
          )}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/processing/automation"
          component={Playbooks}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/processing/automation/:playbookId"
          component={RootPlaybook}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/processing/csv_mapper"
          component={CsvMappers}
        />
        <BoundaryRoute
          exact
          path="/dashboard/data/processing/tasks"
          component={Tasks}
        />
      </Switch></Suspense>
  );
};

export default Root;
