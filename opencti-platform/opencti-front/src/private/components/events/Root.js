import React from 'react';
import { Switch, Redirect } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Incidents from './Incidents';
import RootIncident from './incidents/Root';
import ObservedDatas from './ObservedDatas';
import RootObservedData from './observed_data/Root';
import StixSightingRelationships from './StixSightingRelationships';
import StixSightingRelationship from './stix_sighting_relationships/StixSightingRelationship';

const Root = () => (
  <Switch>
    <BoundaryRoute
      exact
      path="/dashboard/events"
      render={() => <Redirect to="/dashboard/events/incidents" />}
    />
    <BoundaryRoute
      exact
      path="/dashboard/events/incidents"
      component={Incidents}
    />
    <BoundaryRoute
      path="/dashboard/events/incidents/:incidentId"
      component={RootIncident}
    />
    <BoundaryRoute
      exact
      path="/dashboard/events/observed_data"
      component={ObservedDatas}
    />
    <BoundaryRoute
      path="/dashboard/events/observed_data/:observedDataId"
      component={RootObservedData}
    />
    <BoundaryRoute
      exact
      path="/dashboard/events/sightings"
      component={StixSightingRelationships}
    />
    <BoundaryRoute
      exact
      path="/dashboard/events/sightings/:sightingId"
      component={StixSightingRelationship}
    />
  </Switch>
);

export default Root;
