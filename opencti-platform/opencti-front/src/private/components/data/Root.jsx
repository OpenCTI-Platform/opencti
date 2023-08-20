import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import Connectors from './Connectors';
import Entities from './Entities';
import Relationships from './Relationships';
import Tasks from './Tasks';
import Taxii from './Taxii';
import { BoundaryRoute } from '../Error';
import RootConnector from './connectors/Root';
import Stream from './Stream';
import Feed from './Feed';
import Sync from './Sync';
import IngestionRss from './IngestionRss';
import IngestionTaxiis from './IngestionTaxiis';
import Playbooks from './Playbooks';
import RootPlaybook from './playbooks/Root';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/data"
      render={() => <Redirect to="/dashboard/data/entities" />}
    />
    <BoundaryRoute exact path="/dashboard/data/entities" component={Entities} />
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
      render={() => <Redirect to="/dashboard/data/processing/automation" />}
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
      path="/dashboard/data/processing/tasks"
      component={Tasks}
    />
  </Switch>
);

export default Root;
