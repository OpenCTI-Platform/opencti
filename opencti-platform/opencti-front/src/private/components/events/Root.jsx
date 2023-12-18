import React, { Suspense, lazy } from 'react';
import { Redirect, Switch } from 'react-router-dom';
import { BoundaryRoute } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Incidents = lazy(() => import('./Incidents'));
const RootIncident = lazy(() => import('./incidents/Root'));
const ObservedDatas = lazy(() => import('./ObservedDatas'));
const RootObservedData = lazy(() => import('./observed_data/Root'));
const StixSightingRelationships = lazy(() => import('./StixSightingRelationships'));
const StixSightingRelationship = lazy(() => import('./stix_sighting_relationships/StixSightingRelationship'));

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
    <Suspense fallback={<Loader />}>
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
    </Suspense>
  );
};

export default Root;
