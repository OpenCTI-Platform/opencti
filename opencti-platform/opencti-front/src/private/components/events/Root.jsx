import React from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import Incidents from './Incidents';
import RootIncident from './incidents/Root';
import ObservedDatas from './ObservedDatas';
import RootObservedData from './observed_data/Root';
import StixSightingRelationships from './StixSightingRelationships';
import StixSightingRelationship from './stix_sighting_relationships/StixSightingRelationship';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';

const Root = () => {
  let redirect = null;
  if (!useIsHiddenEntity('Incident')) {
    redirect = 'incidents';
  } else if (!useIsHiddenEntity('stix-sighting-relationship')) {
    redirect = 'sightings';
  } else {
    redirect = 'observed_data';
  }
  return (
    <Switch>
      <BoundaryRoute
        exact
        path="/dashboard/events"
        render={() => <Redirect to={`/dashboard/events/${redirect}`} />}
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
};

export default Root;
