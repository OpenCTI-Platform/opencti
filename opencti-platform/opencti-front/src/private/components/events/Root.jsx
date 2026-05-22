import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router';
import { boundaryWrapper } from '../Error';
import { useIsHiddenEntity } from '../../../utils/hooks/useEntitySettings';
import Loader from '../../../components/Loader';

const Incidents = lazy(() => import('./Incidents'));
const RootIncident = lazy(() => import('./incidents/Root'));
const ObservedDatas = lazy(() => import('./ObservedDatas'));
const RootObservedData = lazy(() => import('./observed_data/Root'));
const StixSightingRelationships = lazy(() => import('./StixSightingRelationships'));
const StixSightingRelationship = lazy(() => import('./stix_sighting_relationships/StixSightingRelationship'));

const Root = () => {
  let redirect;
  if (!useIsHiddenEntity('Incident')) {
    redirect = 'incidents';
  } else if (!useIsHiddenEntity('stix-sighting-relationship')) {
    redirect = 'sightings';
  } else {
    redirect = 'observed_data';
  }
  return (
    <Suspense fallback={<Loader />}>
      <Routes>
        <Route
          path="/"
          element={<Navigate to={`/dashboard/events/${redirect}`} replace={true} />}
        />
        <Route path="/incidents">
          <Route index element={boundaryWrapper(Incidents)} />
          <Route path=":incidentId">
            <Route path="*" index element={boundaryWrapper(RootIncident)} />
          </Route>
        </Route>
        <Route path="/observed_data">
          <Route index element={boundaryWrapper(ObservedDatas)} />
          <Route path=":observedDataId">
            <Route path="*" index element={boundaryWrapper(RootObservedData)} />
          </Route>
        </Route>
        <Route path="/sightings">
          <Route index element={boundaryWrapper(StixSightingRelationships)} />
          <Route path=":sightingId">
            <Route path="*" index element={boundaryWrapper(StixSightingRelationship)} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
};

export default Root;
